import json
import os
from collections import deque

import joblib
import numpy as np
from tensorflow.keras.models import load_model
from xgboost import XGBClassifier

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

_XGB = None
_LSTM = None
_FEATURE_COLUMNS = ["packet_rate", "unique_ports", "packets", "ports_per_packet", "burstiness"]
_FEATURE_MEANS = np.zeros(len(_FEATURE_COLUMNS), dtype=np.float32)
_FEATURE_STDS = np.ones(len(_FEATURE_COLUMNS), dtype=np.float32)
_SEQ_LEN = 8
_HISTORY = deque(maxlen=96)
_LOADED = False


def _safe_clip(value, low=0.0, high=100.0):
    return float(max(low, min(high, value)))


def _build_feature_row(packet_rate, unique_ports, packets):
    packet_rate = float(packet_rate)
    unique_ports = float(unique_ports)
    packets = float(max(packets, unique_ports, 1))
    ports_per_packet = unique_ports / packets if packets else 0.0
    burstiness = packet_rate / max(unique_ports, 1.0)
    return np.array(
        [packet_rate, unique_ports, packets, ports_per_packet, burstiness],
        dtype=np.float32,
    )


def _scaled_row(feature_row):
    return (feature_row - _FEATURE_MEANS) / _FEATURE_STDS


def _load_models_once():
    global _XGB, _LSTM, _FEATURE_COLUMNS, _FEATURE_MEANS, _FEATURE_STDS, _SEQ_LEN, _LOADED
    if _LOADED:
        return

    meta_path = os.path.join(MODELS_DIR, "ensemble_meta.json")
    stats_path = os.path.join(MODELS_DIR, "feature_stats.pkl")
    xgb_path = os.path.join(MODELS_DIR, "xgb_model.json")
    lstm_path = os.path.join(MODELS_DIR, "lstm_model.keras")

    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as handle:
                meta = json.load(handle)
                _SEQ_LEN = int(meta.get("seq_len", _SEQ_LEN))
                _FEATURE_COLUMNS = list(meta.get("feature_columns", _FEATURE_COLUMNS))
        except Exception:
            pass

    if os.path.exists(stats_path):
        try:
            stats = joblib.load(stats_path)
            _FEATURE_MEANS = np.array(stats.get("means", _FEATURE_MEANS), dtype=np.float32)
            _FEATURE_STDS = np.array(stats.get("stds", _FEATURE_STDS), dtype=np.float32)
            _FEATURE_STDS[_FEATURE_STDS == 0] = 1.0
        except Exception:
            pass

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


def _rule_signature_score(packet_rate, unique_ports, packets):
    score = 0.0

    # Horizontal scan / nmap sweep.
    if unique_ports >= 10 and packet_rate >= 4:
        score += 40
    if unique_ports >= 18:
        score += 20
    if unique_ports >= 30:
        score += 20
    if unique_ports >= 60:
        score += 10

    # Same-host or slow scan profile.
    if unique_ports >= 12 and packet_rate >= 2:
        score += 10
    if unique_ports >= 20 and packets <= max(unique_ports * 4, 60):
        score += 10

    # Brute-force profile: high volume, low port spread.
    if packet_rate >= 70 and unique_ports <= 4:
        score += 40
    if packets >= 180 and unique_ports <= 3:
        score += 20

    return _safe_clip(score)


def _xgb_score(feature_row):
    if _XGB is None:
        return 0.0

    try:
        proba = float(_XGB.predict_proba(np.asarray([_scaled_row(feature_row)], dtype=np.float32))[0][1])
        return _safe_clip(proba * 100.0)
    except Exception:
        return 0.0


def _lstm_score(feature_row):
    if _LSTM is None:
        return 0.0

    try:
        scaled = _scaled_row(feature_row)
        _HISTORY.append(scaled)
        hist = list(_HISTORY)
        if len(hist) < _SEQ_LEN:
            pad = [hist[0]] * (_SEQ_LEN - len(hist))
            hist = pad + hist
        else:
            hist = hist[-_SEQ_LEN:]

        X_seq = np.asarray([hist], dtype=np.float32)
        proba = float(_LSTM.predict(X_seq, verbose=0)[0][0])
        return _safe_clip(proba * 100.0)
    except Exception:
        return 0.0


def get_ensemble_score(packet_rate, unique_ports, packets=0):
    """
    Returns a 0-100 ensemble anomaly strength.
    This value multiplies the existing Isolation Forest-based score.
    """
    _load_models_once()

    feature_row = _build_feature_row(packet_rate, unique_ports, packets)

    rule_score = _rule_signature_score(packet_rate, unique_ports, packets)
    xgb_score = _xgb_score(feature_row)
    lstm_score = _lstm_score(feature_row)

    final_score = (0.50 * rule_score) + (0.30 * xgb_score) + (0.20 * lstm_score)

    # Immediate amplification for clear nmap behavior, including low-rate same-VM scans.
    if unique_ports >= 20 and packet_rate >= 2:
        final_score = max(final_score, 88.0)

    # Immediate amplification for brute-force behavior.
    if packet_rate >= 90 and unique_ports <= 3:
        final_score = max(final_score, 92.0)

    return int(round(_safe_clip(final_score)))
