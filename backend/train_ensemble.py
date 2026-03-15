import json
import os

import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.layers import Dense, Input, LSTM
from tensorflow.keras.models import Sequential
from xgboost import XGBClassifier

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(BASE_DIR, "data", "behavior.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")

SEQ_LEN = 8
FEATURE_COLUMNS = ["packet_rate", "unique_ports", "packets", "ports_per_packet", "burstiness"]


def _read_behavior_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"behavior dataset not found: {path}")

    df = pd.read_csv(path)

    if "packets" not in df.columns and "packet_count" in df.columns:
        df["packets"] = df["packet_count"]
    if "score" not in df.columns and "scan_score" in df.columns:
        df["score"] = df["scan_score"]

    for column in ["packet_rate", "unique_ports", "packets"]:
        if column not in df.columns:
            df[column] = 0

    if "label" not in df.columns:
        df["label"] = (
            (df.get("score", 0).fillna(0) >= 50)
            | (df["unique_ports"].fillna(0) >= 20)
            | ((df["packet_rate"].fillna(0) >= 80) & (df["unique_ports"].fillna(0) >= 8))
        ).astype(int)

    df = df[["packet_rate", "unique_ports", "packets", "label"]].copy()
    return df.fillna(0)


def _build_synthetic_data(size=3600, seed=42):
    rng = np.random.default_rng(seed)

    benign_size = int(size * 0.42)
    nmap_size = int(size * 0.28)
    brute_size = int(size * 0.18)
    lateral_size = size - benign_size - nmap_size - brute_size

    benign = pd.DataFrame(
        {
            "packet_rate": rng.normal(8, 4, benign_size).clip(0.2, 35),
            "unique_ports": rng.poisson(2.2, benign_size).clip(1, 7),
            "packets": rng.normal(28, 10, benign_size).clip(6, 90),
            "label": np.zeros(benign_size, dtype=int),
        }
    )

    nmap = pd.DataFrame(
        {
            "packet_rate": rng.normal(85, 22, nmap_size).clip(4, 260),
            "unique_ports": rng.integers(14, 220, nmap_size),
            "packets": rng.normal(220, 55, nmap_size).clip(25, 900),
            "label": np.ones(nmap_size, dtype=int),
        }
    )

    brute_force = pd.DataFrame(
        {
            "packet_rate": rng.normal(115, 30, brute_size).clip(10, 420),
            "unique_ports": rng.integers(1, 5, brute_size),
            "packets": rng.normal(360, 70, brute_size).clip(40, 1400),
            "label": np.ones(brute_size, dtype=int),
        }
    )

    lateral = pd.DataFrame(
        {
            "packet_rate": rng.normal(42, 16, lateral_size).clip(2, 180),
            "unique_ports": rng.integers(6, 28, lateral_size),
            "packets": rng.normal(140, 35, lateral_size).clip(18, 600),
            "label": np.ones(lateral_size, dtype=int),
        }
    )

    return pd.concat([benign, nmap, brute_force, lateral], ignore_index=True)


def _engineer_features(df):
    out = df.copy()
    out["ports_per_packet"] = np.where(out["packets"] > 0, out["unique_ports"] / out["packets"], 0.0)
    out["burstiness"] = np.where(out["unique_ports"] > 0, out["packet_rate"] / out["unique_ports"], out["packet_rate"])
    out = out.replace([np.inf, -np.inf], 0).fillna(0)
    return out


def _build_sequences(features, labels, seq_len):
    if len(features) < seq_len:
        pad_rows = np.repeat(features[:1], repeats=seq_len - len(features), axis=0)
        pad_labels = np.repeat(labels[:1], repeats=seq_len - len(labels))
        features = np.vstack([pad_rows, features])
        labels = np.concatenate([pad_labels, labels])

    x_seq = []
    y_seq = []
    for idx in range(seq_len - 1, len(features)):
        start = idx - seq_len + 1
        x_seq.append(features[start : idx + 1])
        y_seq.append(labels[idx])

    return np.asarray(x_seq, dtype=np.float32), np.asarray(y_seq, dtype=np.float32)


def train_and_save():
    os.makedirs(MODELS_DIR, exist_ok=True)

    observed_df = _read_behavior_data(DATASET)
    synthetic_df = _build_synthetic_data()
    all_df = _engineer_features(pd.concat([observed_df, synthetic_df], ignore_index=True))
    all_df = all_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    X = all_df[FEATURE_COLUMNS].astype(np.float32).values
    y = all_df["label"].astype(np.int32).values

    means = X.mean(axis=0)
    stds = X.std(axis=0)
    stds[stds == 0] = 1.0
    X_scaled = (X - means) / stds

    xgb_model = XGBClassifier(
        n_estimators=220,
        max_depth=6,
        learning_rate=0.07,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
    )
    xgb_model.fit(X_scaled, y)
    xgb_model.save_model(os.path.join(MODELS_DIR, "xgb_model.json"))

    X_seq, y_seq = _build_sequences(X_scaled, y, SEQ_LEN)
    lstm_model = Sequential(
        [
            Input(shape=(SEQ_LEN, len(FEATURE_COLUMNS))),
            LSTM(48, activation="tanh"),
            Dense(24, activation="relu"),
            Dense(1, activation="sigmoid"),
        ]
    )
    lstm_model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    lstm_model.fit(X_seq, y_seq, epochs=10, batch_size=32, verbose=0)
    lstm_model.save(os.path.join(MODELS_DIR, "lstm_model.keras"))

    joblib.dump(
        {
            "feature_columns": FEATURE_COLUMNS,
            "means": means.tolist(),
            "stds": stds.tolist(),
        },
        os.path.join(MODELS_DIR, "feature_stats.pkl"),
    )

    with open(os.path.join(MODELS_DIR, "ensemble_meta.json"), "w", encoding="utf-8") as handle:
        json.dump({"seq_len": SEQ_LEN, "feature_columns": FEATURE_COLUMNS}, handle, indent=2)

    print("[ENSEMBLE] Training complete")
    print(f"[ENSEMBLE] Samples: {len(all_df)}")
    print(f"[ENSEMBLE] Model path: {MODELS_DIR}")


if __name__ == "__main__":
    train_and_save()
