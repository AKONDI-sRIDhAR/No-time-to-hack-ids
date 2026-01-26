from scapy.all import sniff, IP, TCP, Ether
from collections import defaultdict
import time
import subprocess
import os
from ml import is_anomalous, log_event

# Configuration
OFFLINE_THRESHOLD = 15  # seconds inactive -> OFFLINE

# Persistent Registry (Tracks all devices seen since startup)
# Format: {ip: {"mac": str, "last_seen": float}}
known_devices = {}

# Cycle Stats (Reset every analysis cycle)
device_stats = defaultdict(lambda: {"ports": set(), "packets": 0})
START_TIME = time.time()

def process_packet(pkt):
    global known_devices
    
    if IP in pkt:
        ip = pkt[IP].src
        now = time.time()
        
        # 1. Update Persistent Registry (Traffic-based presence)
        if ip not in known_devices:
            known_devices[ip] = {"mac": "unknown", "last_seen": now}
        else:
            known_devices[ip]["last_seen"] = now

        # Update MAC if available
        if Ether in pkt:
            known_devices[ip]["mac"] = pkt[Ether].src

        # 2. Update Cycle Stats
        device_stats[ip]["packets"] += 1
        if TCP in pkt:
            device_stats[ip]["ports"].add(pkt[TCP].dport)

def analyze_traffic():
    global START_TIME, device_stats
    
    now = time.time()
    duration = max(now - START_TIME, 1)
    
    threats = []
    active_devices = []

    # Iterate over ALL known devices (not just active ones)
    for ip, info in known_devices.items():
        # Determine OFFLINE state based on last_seen
        time_since_seen = now - info["last_seen"]
        is_offline = time_since_seen > OFFLINE_THRESHOLD
        
        # Get stats for this cycle (default to 0 if no packets)
        stats = device_stats.get(ip, {"ports": set(), "packets": 0})
        
        packet_rate = stats["packets"] / duration
        unique_ports = len(stats["ports"])
        
        # Default Status
        status = "OFFLINE" if is_offline else "ONLINE"
        score_val = 0
        
        # Only run ML/Anomaly detection if device is ONLINE (acting)
        if not is_offline:
            anomalous, score_str = is_anomalous(packet_rate, unique_ports)
            try:
                # Extract numeric score from string "50 (Explanation)"
                score_val = int(score_str.split(" ")[0])
            except:
                score_val = 0
                
            label = 1 if anomalous else 0
            
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
            
            if anomalous:
                status = "SUSPICIOUS"
                threats.append({"ip": ip, "score": score_val})

        # Add to Dashboard List
        active_devices.append({
            "ip": ip,
            "mac": info["mac"],
            "packets": stats["packets"], # Packets in *this* window
            "ports": unique_ports,
            "status": status,
            "last_seen": round(time_since_seen, 1)
        })

    # Reset Cycle Stats
    device_stats = defaultdict(lambda: {"ports": set(), "packets": 0})
    START_TIME = time.time()
    
    return threats, active_devices

def start_ids_cycle(timeout=5):
    try:
        sniff(prn=process_packet, store=False, timeout=timeout)
        return analyze_traffic()
    except Exception as e:
        print(f"[IDS] Error: {e}")
        return [], []
