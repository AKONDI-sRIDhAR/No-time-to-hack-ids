import pandas as pd
import os
import threading
from sklearn.ensemble import IsolationForest
from ensemble_ml import get_ensemble_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATASET = os.path.join(DATA_DIR, "behavior.csv")

class Brain:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_fitted = False
        self.lock = threading.Lock() # Fix: Thread safety for sklearn
        self.events_since_train = 0
        self.ensure_dataset()

    def ensure_dataset(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(DATASET):
            with open(DATASET, "w") as f:
                # Matches backend/ids.py logging order
                f.write("timestamp,ip,mac,packet_rate,packets,unique_ports,score,label\n")

    def load_data(self):
        try:
            if not os.path.exists(DATASET):
                return pd.DataFrame()

            # Check if file has enough data (more than just header)
            if os.path.getsize(DATASET) < 50:
                return pd.DataFrame()
                
            df = pd.read_csv(DATASET)
            # Backward compatibility with old headers.
            if "packets" not in df.columns and "packet_count" in df.columns:
                df["packets"] = df["packet_count"]
            if "score" not in df.columns and "scan_score" in df.columns:
                df["score"] = df["scan_score"]
            return df
        except Exception as e:
            print(f"[ML] Error loading data: {e}")
            return pd.DataFrame()

    def train(self):
        df = self.load_data()
        
        # Need enough data to train
        if df.empty or len(df) < 10:
            return

        try:
            if "packet_rate" in df.columns and "unique_ports" in df.columns:
                X = df[["packet_rate", "unique_ports"]]
                
                with self.lock: # Fix: Lock during training
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

                with self.lock: # Fix: Lock during prediction
                    pred = self.model.predict(X_test)[0]
                    
                if pred == -1:
                    score += 30
                    explanation.append("ML Anomaly Detected")
            except Exception:
                pass

        ensemble_score = get_ensemble_score(packet_rate, unique_ports)
        score = min(100, int(score * (1 + (ensemble_score / 100.0))))
        if ensemble_score >= 60:
            explanation.append("Port Scan Detected (Ensemble ML)")

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
    # Retrain on a deterministic cadence to avoid long stale windows.
    brain.events_since_train += 1
    if brain.events_since_train >= 20:
        brain.train()
        brain.events_since_train = 0
