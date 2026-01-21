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
                f.write("timestamp,ip,mac,packet_rate,port_count,unique_ports,scan_score,label\n")

    def load_data(self):
        try:
            df = pd.read_csv(DATASET)
            return df
        except Exception as e:
            print(f"[ML] Error loading data: {e}")
            return pd.DataFrame()

    def train(self):
        df = self.load_data()
        if len(df) > 10:  # Train only if we have enough data
            # Features: packet_rate, unique_ports
            X = df[["packet_rate", "unique_ports"]]
            self.model.fit(X)
            self.is_fitted = True
            print("[ML] Model retrained with new data.")

    def analyze(self, packet_rate, unique_ports):
        """
        Returns (is_anomalous, score_explanation)
        """
        # 1. Rule-based fallback/explanation (Z-Score style or thresholds)
        score = 0
        explanation = []
        
        if packet_rate > 100:
            score += 50
            explanation.append("High Packet Rate")
        if unique_ports > 20:
            score += 50
            explanation.append("Port Scan Detected")

        # 2. ML Validation
	if self.is_fitted:
		X_test = pd.DataFrame(
        		[[packet_rate, unique_ports]],
        		columns=["packet_rate", "unique_ports"]
    		)

    		pred = self.model.predict(X_test)[0]
    		if pred == -1:
        		score += 30
        		explanation.append("ML Anomaly Detected")

        is_anomalous = score >= 50
        return is_anomalous, f"{score} ({', '.join(explanation)})"

    def log_event(self, row):
        # row: timestamp,ip,mac,packet_rate,port_count,unique_ports,scan_score,label
        with open(DATASET, "a") as f:
            f.write(",".join(map(str, row)) + "\n")
        
        # Trigger Retrain occasionally or simply rely on periodic checks? 
        # For simplicity, we won't retrain on *every* log, but maybe main loop triggers it.

brain = Brain()

def is_anomalous(packet_rate, unique_ports):
    return brain.analyze(packet_rate, unique_ports)

def log_event(row):
    brain.log_event(row)
    # Simple auto-retrain trigger
    if np.random.rand() < 0.1: # 10% chance to retrain on log to keep it fresh
        brain.train()
