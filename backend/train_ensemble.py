import json
import os

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from tensorflow.keras.layers import Dense, Input, LSTM
from tensorflow.keras.models import Sequential

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(BASE_DIR, "data", "behavior.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")

SEQ_LEN = 6


def _read_behavior_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"behavior dataset not found: {path}")

    df = pd.read_csv(path)

    if "packets" not in df.columns and "packet_count" in df.columns:
        df["packets"] = df["packet_count"]
    if "score" not in df.columns and "scan_score" in df.columns:
        df["score"] = df["scan_score"]

    for col in ["packet_rate", "unique_ports"]:
        if col not in df.columns:
            df[col] = 0

    if "label" not in df.columns:
        df["label"] = ((df.get("score", 0) >= 50) | (df["unique_ports"] >= 20)).astype(int)

    df = df[["packet_rate", "unique_ports", "label"]].copy()
    df = df.fillna(0)
    return df


def _build_synthetic_data(size=2400, seed=42):
    rng = np.random.default_rng(seed)

    benign_size = int(size * 0.45)
    scan_size = size - benign_size

    benign_packet = rng.normal(loc=9, scale=4, size=benign_size).clip(0.1, 45)
    benign_ports = rng.poisson(lam=2.0, size=benign_size).clip(1, 8)

    scan_packet = rng.normal(loc=110, scale=38, size=scan_size).clip(15, 550)
    scan_ports = rng.integers(low=18, high=140, size=scan_size)

    # Hard signatures for SYN sweep behavior (same VM included).
    syn_packet = rng.normal(loc=70, scale=18, size=scan_size // 3).clip(10, 300)
    syn_ports = rng.integers(low=30, high=260, size=scan_size // 3)

    packet_rate = np.concatenate([benign_packet, scan_packet, syn_packet])
    unique_ports = np.concatenate([benign_ports, scan_ports, syn_ports])
    labels = np.concatenate([
        np.zeros(benign_size, dtype=int),
        np.ones(scan_size, dtype=int),
        np.ones(scan_size // 3, dtype=int),
    ])

    synthetic = pd.DataFrame(
        {
            "packet_rate": packet_rate,
            "unique_ports": unique_ports,
            "label": labels,
        }
    )
    return synthetic


def _build_sequences(array_2d, labels, seq_len):
    if len(array_2d) < seq_len:
        pad = np.repeat(array_2d[:1], repeats=seq_len - len(array_2d), axis=0)
        array_2d = np.vstack([pad, array_2d])
        labels = np.concatenate([np.repeat(labels[:1], repeats=seq_len - len(labels)), labels])

    x_seq = []
    y_seq = []
    for idx in range(seq_len - 1, len(array_2d)):
        start = idx - seq_len + 1
        x_seq.append(array_2d[start : idx + 1])
        y_seq.append(labels[idx])

    return np.asarray(x_seq, dtype=np.float32), np.asarray(y_seq, dtype=np.float32)


def train_and_save():
    os.makedirs(MODELS_DIR, exist_ok=True)

    base_df = _read_behavior_data(DATASET)
    synth_df = _build_synthetic_data()

    all_df = pd.concat([base_df, synth_df], ignore_index=True)
    all_df = all_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    X = all_df[["packet_rate", "unique_ports"]].astype(float).values
    y = all_df["label"].astype(int).values

    xgb_model = XGBClassifier(
        n_estimators=160,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
    )
    xgb_model.fit(X, y)
    xgb_model.save_model(os.path.join(MODELS_DIR, "xgb_model.json"))

    scaler = joblib.dump(
        {
            "mean_packet_rate": float(np.mean(X[:, 0])),
            "mean_unique_ports": float(np.mean(X[:, 1])),
        },
        os.path.join(MODELS_DIR, "feature_stats.pkl"),
    )

    # LSTM trains on temporal windows built from shuffled attack+benign patterns.
    X_seq, y_seq = _build_sequences(X, y, SEQ_LEN)

    model = Sequential(
        [
            Input(shape=(SEQ_LEN, 2)),
            LSTM(24, activation="tanh"),
            Dense(12, activation="relu"),
            Dense(1, activation="sigmoid"),
        ]
    )

    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.fit(X_seq, y_seq, epochs=8, batch_size=32, verbose=0)
    model.save(os.path.join(MODELS_DIR, "lstm_model.keras"))

    with open(os.path.join(MODELS_DIR, "ensemble_meta.json"), "w", encoding="utf-8") as f:
        json.dump({"seq_len": SEQ_LEN}, f, indent=2)

    print("[ENSEMBLE] Training complete")
    print(f"[ENSEMBLE] Saved models to: {MODELS_DIR}")


if __name__ == "__main__":
    train_and_save()