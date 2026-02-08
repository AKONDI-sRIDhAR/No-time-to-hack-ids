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

class CorrelationEngine:
    def __init__(self):
        pass

    def correlate(self, threats):
        """
        Correlates recent IDS anomalies with Honeypot logs to escalate threats.
        Returns updated threats list with explanation.
        """
        # Load recent honeypot interactions
        # This checks if an IP that triggered IDS also touched a honeypot
        hp_logs = self.load_recent_honeypot_activity()
        
        updated_threats = []
        for threat in threats:
            ip = threat.get("ip")
            # Check if this IP is in honeypot logs
            if ip and ip in hp_logs:
                # CORRELATION DETECTED: Anomaly + Deception Interaction
                # Escalate score
                threat["score"] = min(100, threat.get("score", 0) + 30)
                threat["trust"] = max(0, threat.get("trust", 50) - TRUST_LOSS_HONEYPOT)
                threat["correlation"] = f"Correlation: Anomaly + Honeypot Interaction ({hp_logs[ip]} events)"
                if "flags" in threat:
                    threat["flags"]["redirected"] = True # Ensure redirection is active
            updated_threats.append(threat)
        
        return updated_threats

    def load_recent_honeypot_activity(self):
        """
        Returns {ip: count} of unique IPs seen in honeypot logs recently.
        """
        activity = {}
        if not os.path.exists(HONEYPOT_CSV):
            return activity
            
        try:
            # Check if file has content
            if os.path.getsize(HONEYPOT_CSV) < 50:
                return activity

            df = pd.read_csv(HONEYPOT_CSV)
            if df.empty: return activity
            
            # Simplified: Just check if IP exists in "recent" rows (last 50)
            recent = df.tail(50)
            if "source_ip" in recent.columns:
                for ip in recent["source_ip"].unique():
                    count = len(recent[recent["source_ip"] == ip])
                    activity[ip] = count
                
        except Exception as e:
            print(f"[CORRELATION] Error: {e}")
            pass
        return activity

correlator = CorrelationEngine()

def correlate_threats(threats):
    return correlator.correlate(threats)
