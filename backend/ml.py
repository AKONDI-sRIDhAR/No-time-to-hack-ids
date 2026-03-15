import os
import threading

import pandas as pd
from sklearn.ensemble import IsolationForest

try:
    from ensemble_ml import get_ensemble_score
except Exception:
    def get_ensemble_score(packet_rate, unique_ports, packets=0):
        return 0


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATASET = os.path.join(DATA_DIR, "behavior.csv")


class Brain:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_fitted = False
        self.lock = threading.Lock()
        self.events_since_train = 0
        self.ensure_dataset()

    def ensure_dataset(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(DATASET):
            with open(DATASET, "w", encoding="utf-8") as handle:
                handle.write("timestamp,ip,mac,packet_rate,packets,unique_ports,score,label\n")

    def load_data(self):
        try:
            if not os.path.exists(DATASET) or os.path.getsize(DATASET) < 50:
                return pd.DataFrame()

            df = pd.read_csv(DATASET)
            if "packets" not in df.columns and "packet_count" in df.columns:
                df["packets"] = df["packet_count"]
            if "score" not in df.columns and "scan_score" in df.columns:
                df["score"] = df["scan_score"]
            return df
        except Exception as exc:
            print(f"[ML] Error loading data: {exc}")
            return pd.DataFrame()

    def train(self):
        df = self.load_data()
        if df.empty or len(df) < 10:
            return

        try:
            if "packet_rate" in df.columns and "unique_ports" in df.columns:
                X = df[["packet_rate", "unique_ports"]]
                with self.lock:
                    self.model.fit(X)
                    self.is_fitted = True
                print("[ML] Model retrained with new data.")
        except Exception as exc:
            print(f"[ML] Training failed: {exc}")

    def analyze(self, packet_rate, unique_ports, packets=0):
        """
        Returns (is_anomalous, score_explanation, final_score, ensemble_score)
        """
        score = 0
        explanation = []

        if packet_rate > 100:
            score += 50
            explanation.append("High Packet Rate")

        if unique_ports > 20:
            score += 50
            explanation.append("Port Scan Detected")

        if self.is_fitted:
            try:
                X_test = pd.DataFrame([[packet_rate, unique_ports]], columns=["packet_rate", "unique_ports"])
                with self.lock:
                    pred = self.model.predict(X_test)[0]
                if pred == -1:
                    score += 30
                    explanation.append("ML Anomaly Detected")
            except Exception:
                pass

        ensemble_score = get_ensemble_score(packet_rate, unique_ports, packets)
        score = min(100, int(score * (1 + (ensemble_score / 100.0))))

        if ensemble_score >= 60:
            explanation.append("Ensemble Signature Match")
        if ensemble_score >= 85:
            explanation.append("Autonomous Escalation Ready")

        is_anomalous = score >= 50
        explanation_text = ", ".join(explanation) if explanation else "Normal"
        return is_anomalous, f"{score} ({explanation_text})", score, ensemble_score

    def log_event(self, row):
        try:
            with open(DATASET, "a", encoding="utf-8") as handle:
                handle.write(",".join(map(str, row)) + "\n")
        except Exception:
            pass


brain = Brain()


def is_anomalous(packet_rate, unique_ports, packets=0):
    return brain.analyze(packet_rate, unique_ports, packets)


def log_event(row):
    brain.log_event(row)
    brain.events_since_train += 1
    if brain.events_since_train >= 20:
        brain.train()
        brain.events_since_train = 0
