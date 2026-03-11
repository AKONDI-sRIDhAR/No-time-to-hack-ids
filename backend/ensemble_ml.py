import json
import os
from collections import deque

import numpy as np
from xgboost import XGBClassifier
from tensorflow.keras.models import load_model

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

_XGB = None
_LSTM = None
_SEQ_LEN = 6
_HISTORY = deque(maxlen=64)
_LOADED = False


def _safe_clip(value, low=0.0, high=100.0):
    return float(max(low, min(high, value)))


def _load_models_once():
    global _XGB, _LSTM, _SEQ_LEN, _LOADED
    if _LOADED:
        return

    meta_path = os.path.join(MODELS_DIR, "ensemble_meta.json")
    xgb_path = os.path.join(MODELS_DIR, "xgb_model.json")
    lstm_path = os.path.join(MODELS_DIR, "lstm_model.keras")

    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                _SEQ_LEN = int(json.load(f).get("seq_len", 6))
        except Exception:
            _SEQ_LEN = 6

    if os.path.exists(xgb_path):
        try:
            _XGB = XGBClassifier()
            _XGB.load_model(xgb_path)
        except Exception:
            _XGB = None

    if os.path.exists(lstm_path):
        try:
            _LSTM = load_model(lstm_path, compile=False)
        except Exception:
            _LSTM = None

    _LOADED = True


def _rule_signature_score(packet_rate, unique_ports):
    score = 0.0

    # Nmap SYN sweep / horizontal scan profile.
    if unique_ports >= 12 and packet_rate >= 8:
        score += 55
    if unique_ports >= 20:
        score += 30
    if unique_ports >= 40:
        score += 20
    if packet_rate >= 80:
        score += 15

    return _safe_clip(score)


def _xgb_score(packet_rate, unique_ports):
    if _XGB is None:
        return 0.0

    try:
        X = np.array([[float(packet_rate), float(unique_ports)]], dtype=np.float32)
        proba = float(_XGB.predict_proba(X)[0][1])
        return _safe_clip(proba * 100.0)
    except Exception:
        return 0.0


def _lstm_score(packet_rate, unique_ports):
    if _LSTM is None:
        return 0.0

    try:
        _HISTORY.append([float(packet_rate), float(unique_ports)])

        if not _HISTORY:
            return 0.0

        hist = list(_HISTORY)
        if len(hist) < _SEQ_LEN:
            pad = [hist[0]] * (_SEQ_LEN - len(hist))
            hist = pad + hist
        else:
            hist = hist[-_SEQ_LEN:]

        X_seq = np.array([hist], dtype=np.float32)
        proba = float(_LSTM.predict(X_seq, verbose=0)[0][0])
        return _safe_clip(proba * 100.0)
    except Exception:
        return 0.0


def get_ensemble_score(packet_rate, unique_ports):
    """
    Returns a 0-100 ensemble anomaly strength.
    This value is designed to multiply the existing Isolation Forest-based score.
    """
    _load_models_once()

    packet_rate = float(packet_rate)
    unique_ports = float(unique_ports)

    rule_score = _rule_signature_score(packet_rate, unique_ports)
    xgb_score = _xgb_score(packet_rate, unique_ports)
    lstm_score = _lstm_score(packet_rate, unique_ports)

    # Weighted blend tuned to prefer deterministic scan signatures.
    final_score = (0.45 * rule_score) + (0.30 * xgb_score) + (0.25 * lstm_score)

    # Hard floor so obvious scans from same VM are immediately amplified.
    if unique_ports >= 25 and packet_rate >= 5:
        final_score = max(final_score, 85.0)

    return int(round(_safe_clip(final_score)))