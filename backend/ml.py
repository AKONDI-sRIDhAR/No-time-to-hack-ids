import pandas as pd
import numpy as np
import os
from datetime import datetime
from sklearn.ensemble import IsolationForest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATASET = os.path.join(DATA_DIR, "behavior.csv")

class Brain:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_fitted = False
        self.ensure_dataset()

    def ensure_dataset(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(DATASET):
            with open(DATASET, "w") as f:
                f.write(
                    "timestamp,ip,mac,packet_rate,packet_count,unique_ports,scan_score,label\n"
                )

    def load_data(self):
        try:
            # Check if file is empty (just header)
            if os.path.getsize(DATASET) < 100: # Arbitrary small size check
                return pd.DataFrame()
                
            df = pd.read_csv(DATASET)
            return df
        except Exception as e:
            print(f"[ML] Error loading data: {e}")
            return pd.DataFrame()

    def train(self):
        df = self.load_data()
        
        # Robust check for empty or insufficient data
        if df.empty or len(df) < 10:
            return

        try:
            # Ensure numeric columns exist and are valid
            if "packet_rate" in df.columns and "unique_ports" in df.columns:
                X = df[["packet_rate", "unique_ports"]]
                self.model.fit(X)
                self.is_fitted = True
                print("[ML] Model retrained with new data.")
        except Exception as e:
            print(f"[ML] Training failed: {e}")

    def analyze(self, packet_rate, unique_ports):
        """
        Returns (is_anomalous, score_explanation)
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
                X_test = pd.DataFrame(
                    [[packet_rate, unique_ports]],
                    columns=["packet_rate", "unique_ports"]
                )

                pred = self.model.predict(X_test)[0]
                if pred == -1:
                    score += 30
                    explanation.append("ML Anomaly Detected")
            except Exception:
                pass

        is_anomalous = score >= 50
        return is_anomalous, f"{score} ({', '.join(explanation)})"

    def log_event(self, row):
        try:
            with open(DATASET, "a") as f:
                f.write(",".join(map(str, row)) + "\n")
        except Exception:
            pass

brain = Brain()

def is_anomalous(packet_rate, unique_ports):
    return brain.analyze(packet_rate, unique_ports)

def log_event(row):
    brain.log_event(row)
    if np.random.rand() < 0.1:
        brain.train()
