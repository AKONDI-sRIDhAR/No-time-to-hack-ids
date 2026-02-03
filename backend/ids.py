from scapy.all import sniff, IP, TCP, Ether
from collections import defaultdict
import time
import subprocess
import os
from ml import is_anomalous, log_event

# Configuration
OFFLINE_THRESHOLD = 15  # seconds inactive -> OFFLINE

# Persistent Registry (Tracks all devices seen since startup)
# Format: {ip: {
#   "mac": str, 
#   "last_seen": float, 
#   "first_seen": float,
#   "trust_score": int (0-100), 
#   "flags": {"redirected": bool, "isolated": bool, "quarantined": bool}
# }}
import json

# Persistent Registry Configuration
DEVICES_FILE = "backend/data/devices.json"

def load_devices():
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_devices():
    os.makedirs(os.path.dirname(DEVICES_FILE), exist_ok=True)
    with open(DEVICES_FILE, "w") as f:
        json.dump(known_devices, f, indent=4)

known_devices = load_devices()

# Cycle Stats (Reset every analysis cycle)
device_stats = defaultdict(lambda: {"ports": set(), "packets": 0})
START_TIME = time.time()

def process_packet(pkt):
    global known_devices
    
    if IP in pkt:
        ip = pkt[IP].src
        now = time.time()
        
        # 1. Update Persistent Registry & Trust Initialization
        if ip not in known_devices:
            known_devices[ip] = {
                "mac": "unknown", 
                "last_seen": now,
                "first_seen": now,
                "trust_score": 50, # New devices start neutral/quarantined
                "flags": {"redirected": False, "isolated": False, "quarantined": True} 
            }
        else:
            known_devices[ip]["last_seen"] = now

        # Update MAC if available
        if Ether in pkt:
            known_devices[ip]["mac"] = pkt[Ether].src

        # 2. Update Cycle Stats
        device_stats[ip]["packets"] += 1
        if TCP in pkt:
            device_stats[ip]["ports"].add(pkt[TCP].dport)

def update_trust_score(ip, info, anomalous, packet_rate, unique_ports):
    """
    Updates the Trust Score (0-100) based on behavior.
    """
    score = info["trust_score"]
    
    # Penalties
    if anomalous:
        score -= 20  # Anomaly Penalty
    if unique_ports > 10:
        score -= 10  # Scanning Penalty
    if packet_rate > 50:
        score -= 5   # Flooding Penalty

    # Rewards (Gradual Trust Building)
    if not anomalous and unique_ports < 5:
        score += 1   # Good Behavior Reward
        
    # Clamp Score
    score = max(0, min(100, score))
    
    return score

def analyze_traffic():
    global START_TIME, device_stats
    
    now = time.time()
    duration = max(now - START_TIME, 1)
    
    threats = []
    active_devices = []

    # Iterate over ALL known devices
    for ip, info in known_devices.items():
        # Determine OFFLINE state
        time_since_seen = now - info["last_seen"]
        is_offline = time_since_seen > OFFLINE_THRESHOLD
        
        # Get stats for this cycle
        stats = device_stats.get(ip, {"ports": set(), "packets": 0})
        packet_rate = stats["packets"] / duration
        unique_ports = len(stats["ports"])
        
        label = 0
        score_val = 0
        
        if not is_offline:
            # 1. Anomaly Detection
            anomalous, score_str = is_anomalous(packet_rate, unique_ports)
            try:
                score_val = int(score_str.split(" ")[0])
            except:
                score_val = 0
            label = 1 if anomalous else 0

            # 2. Update Trust Score
            new_trust = update_trust_score(ip, info, anomalous, packet_rate, unique_ports)
            known_devices[ip]["trust_score"] = new_trust
            
            # 3. Quarantine Logic (New Device Probation)
            if info["flags"]["quarantined"]:
                if new_trust > 70 and (now - info["first_seen"] > 60):
                    known_devices[ip]["flags"]["quarantined"] = False # Lift Quarantine
            
            # 4. Protection Flags Logic (Derived from Trust)
            if new_trust < 40:
                known_devices[ip]["flags"]["redirected"] = True # Deceive
            if new_trust < 20: 
                known_devices[ip]["flags"]["isolated"] = True   # Contain

            # Log to CSV
            row = [
                time.strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                info["mac"],
                round(packet_rate, 2),
                stats["packets"],
                unique_ports,
                score_val,
                label
            ]
            log_event(row)
            
            if anomalous or known_devices[ip]["flags"]["redirected"]:
                # Basic Explanation
                reasons = []
                if anomalous: reasons.append(f"Anomaly (Score {score_val})")
                if packet_rate > 50: reasons.append("High Rate")
                if unique_ports > 10: reasons.append("Port Scan")
                
                threat_entry = {
                    "ip": ip, 
                    "score": score_val, 
                    "trust": new_trust,
                    "flags": known_devices[ip]["flags"],
                    "reason": ", ".join(reasons)
                }
                threats.append(threat_entry)
                
    # 4️⃣ Protocol & App-Layer Correlation Engine usage
    # We do a pass after collecting all threats
    if threats:
        from correlation import correlate_threats
        threats = correlate_threats(threats)

        # Re-sync Trust Score based on correlation
        for t in threats:
            if "correlation" in t:
                known_devices[t["ip"]]["trust_score"] = t["trust"]
                known_devices[t["ip"]]["flags"] = t["flags"] # Update flags if correlation forced redirection

        # Determine Status String for Dashboard
        status = "ONLINE"
        if is_offline: status = "OFFLINE"
        elif info["flags"]["isolated"]: status = "CONTAINED"
        elif info["flags"]["redirected"]: status = "DECEIVED"
        elif info["flags"]["quarantined"]: status = "NEW/QUARANTINED"
        elif label == 1: status = "SUSPICIOUS"

        active_devices.append({
            "ip": ip,
            "mac": info["mac"],
            "packets": stats["packets"],
            "ports": unique_ports,
            "status": status,
            "trust_score": info["trust_score"], # Exposed to UI
            "last_seen": round(time_since_seen, 1),
            "flags": info["flags"]              # Exposed to UI
        })

    # Reset Cycle Stats
    device_stats = defaultdict(lambda: {"ports": set(), "packets": 0})
    START_TIME = time.time()
    
    save_devices() # Persist state
    
    return threats, active_devices

def start_ids_cycle(timeout=5):
    try:
        sniff(prn=process_packet, store=False, timeout=timeout)
        return analyze_traffic()
    except Exception as e:
        print(f"[IDS] Error: {e}")
        return [], []
