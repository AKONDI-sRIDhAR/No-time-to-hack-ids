import pandas as pd
import numpy as np
import os
import time

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
BEHAVIOR_CSV = os.path.join(DATA_DIR, "behavior.csv")
HONEYPOT_CSV = os.path.join(DATA_DIR, "honeypot.csv")

# Constants
TRUST_LOSS_HONEYPOT = 40
TRUST_GAIN_HOUR = 5

class CorrelationEngine:
    def __init__(self):
        self.ensure_csvs()

    def ensure_csvs(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(BEHAVIOR_CSV):
            with open(BEHAVIOR_CSV, "w") as f:
                f.write("timestamp,ip,mac,packet_rate,port_count,unique_ports,scan_score,label\n")
        # Honeypot CSV created by docker_honeypot.py

    def correlate(self, threats):
        """
        Correlates recent IDS anomalies with Honeypot logs to escalate threats.
        Returns updated threats list with explanation.
        """
        # Load recent honeypot interactions
        hp_logs = self.load_recent_honeypot_activity(minutes=5)
        
        for threat in threats:
            ip = threat["ip"]
            # Check if this IP is in honeypot logs
            if ip in hp_logs:
                # CORRELATION DETECTED: Anomaly + Deception Interaction
                # Escalate score
                threat["score"] = min(100, threat["score"] + 30)
                threat["trust"] = max(0, threat["trust"] - TRUST_LOSS_HONEYPOT)
                threat["correlation"] = f"Correlation: Anomaly + Honeypot Interaction ({hp_logs[ip]} events)"
                threat["flags"]["redirected"] = True # Ensure redirection is active
        
        return threats

    def load_recent_honeypot_activity(self, minutes=5):
        """
        Returns {ip: count} of unique IPs seen in honeypot logs recently.
        """
        activity = {}
        if not os.path.exists(HONEYPOT_CSV):
            return activity
            
        try:
            # Simple tail parse (optimization: read reverse)
            # For prototype, reading full file is okay if small, but let's be safer.
            # We assume regular log rotation or small size for this scope.
            df = pd.read_csv(HONEYPOT_CSV)
            if df.empty: return activity
            
            # Filter by time? 
            # Since logging is just appending strings, parsing timestamps is costly.
            # Simplified: Just check if IP exists in "recent" rows (last 50)
            recent = df.tail(50)
            for ip in recent["source_ip"].unique():
                activity[ip] = len(recent[recent["source_ip"] == ip])
                
        except Exception:
            pass
        return activity

correlator = CorrelationEngine()

def correlate_threats(threats):
    return correlator.correlate(threats)
