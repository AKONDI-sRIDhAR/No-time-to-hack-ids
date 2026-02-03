from scapy.all import sniff, IP, TCP, Ether, ARP
from collections import defaultdict
import time
import subprocess
import os
import json
from ml import is_anomalous, log_event

# Configuration
OFFLINE_THRESHOLD = 30  # seconds inactive -> OFFLINE
DEVICES_FILE = "backend/data/devices.json"

# Persistent Registry Format:
# {
#   "MAC_ADDR": {
#       "ip": "1.2.3.4",
#       "hostname": "foo",
#       "first_seen": ts,
#       "last_seen": ts,
#       "trust_score": 50,
#       "flags": {"redirected": False, "isolated": False, "quarantined": True}
#   }
# }
known_devices = {}

# Cycle Stats: {MAC: {"ports": set, "packets": int}}
device_stats = defaultdict(lambda: {"ports": set(), "packets": 0})
START_TIME = time.time()

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

def get_dhcp_leases():
    """Parses dnsmasq leases for authoritative device info."""
    leases = {}
    possible_paths = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
        "/var/lib/dhcp/dhcpd.leases" 
    ]
    
    lease_file = None
    for p in possible_paths:
        if os.path.exists(p):
            lease_file = p
            break
            
    if lease_file:
        try:
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        # Format: timestamp mac ip hostname clientid
                        mac = parts[1]
                        leases[mac] = {"ip": parts[2], "hostname": parts[3]}
        except Exception:
            pass
    return leases

def get_arp_table():
    """Parses system ARP table."""
    arp_entries = {}
    try:
        # Using ip neigh for better reliability than /proc/net/arp
        output = subprocess.check_output(["ip", "neigh"], text=True)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                # 192.168.10.X dev wlan0 lladdr AA:BB:CC:DD:EE:FF STALE/REACHABLE
                ip = parts[0]
                mac = parts[4]
                state = parts[-1] 
                if state not in ["FAILED", "INCOMPLETE"]:
                    arp_entries[mac] = ip
    except Exception:
        pass
    return arp_entries

def scan_network_state():
    """
    Updates known_devices based on DHCP and ARP.
    This is the PREMIER source of truth for presence.
    """
    global known_devices
    now = time.time()
    
    dhcp = get_dhcp_leases()
    arp = get_arp_table()
    
    # Merge sources
    observed_macs = set(dhcp.keys()).union(set(arp.keys()))
    
    for mac in observed_macs:
        ip = arp.get(mac, dhcp.get(mac, {}).get("ip", "0.0.0.0"))
        hostname = dhcp.get(mac, {}).get("hostname", "unknown")
        
        if mac not in known_devices:
            known_devices[mac] = {
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "first_seen": now,
                "last_seen": now,
                "trust_score": 50,
                "flags": {"redirected": False, "isolated": False, "quarantined": True}
            }
        else:
            known_devices[mac]["last_seen"] = now
            # Update IP if changed
            if ip != "0.0.0.0":
                known_devices[mac]["ip"] = ip
            if hostname != "unknown":
                known_devices[mac]["hostname"] = hostname

def process_packet(pkt):
    """
    Scapy callback. ONLY updates statistics.
    Does NOT register new devices (that's DHCP/ARP's job).
    """
    global device_stats
    
    if Ether in pkt:
        mac = pkt[Ether].src
        
        # Only track stats for devices we roughly know or are broadcasting
        device_stats[mac]["packets"] += 1
        
        if TCP in pkt:
            device_stats[mac]["ports"].add(pkt[TCP].dport)

def update_trust_score(info, anomalous, packet_rate, unique_ports):
    score = info["trust_score"]
    
    if anomalous: score -= 20
    if unique_ports > 10: score -= 10
    if packet_rate > 50: score -= 5
    if not anomalous and unique_ports < 5: score += 1
        
    return max(0, min(100, score))

def analyze_traffic():
    global START_TIME, device_stats
    
    # 1. Update Presence
    scan_network_state()
    
    now = time.time()
    duration = max(now - START_TIME, 1)
    
    threats = []
    active_devices = []

    # Iterate over Registry (MAC is key)
    for mac, info in known_devices.items():
        ip = info.get("ip", "0.0.0.0")
        
        # Determine OFFLINE state
        # A device is offline if not seen in ARP/DHCP scan AND not sending packets for threshold
        time_since_seen = now - info["last_seen"]
        
        # Check Scapy stats for this cycle (maybe we saw packets but ARP didn't update yet)
        stats = device_stats.get(mac, {"ports": set(), "packets": 0})
        if stats["packets"] > 0:
            info["last_seen"] = now
            time_since_seen = 0 # Active right now
            
        is_offline = time_since_seen > OFFLINE_THRESHOLD
        
        packet_rate = stats["packets"] / duration
        unique_ports = len(stats["ports"])
        
        label = 0
        score_val = 0
        
        # Logic Loop
        if not is_offline:
            # 1. Anomaly Check
            anomalous, score_str = is_anomalous(packet_rate, unique_ports)
            try:
                score_val = int(score_str.split(" ")[0])
            except:
                score_val = 0
            label = 1 if anomalous else 0

            # 2. Trust Score
            new_trust = update_trust_score(info, anomalous, packet_rate, unique_ports)
            known_devices[mac]["trust_score"] = new_trust
            
            # 3. Lifecycle Logic
            # Lift Quarantine?
            if info["flags"]["quarantined"] and new_trust > 70 and (now - info["first_seen"] > 60):
                known_devices[mac]["flags"]["quarantined"] = False
            
            # Degrade?
            if new_trust < 40: known_devices[mac]["flags"]["redirected"] = True
            if new_trust < 20: known_devices[mac]["flags"]["isolated"] = True

            # 4. Log to CSV
            # timestamp,ip,mac,pkt_rate,pkts,ports,score,label
            row = [
                time.strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                mac,
                round(packet_rate, 2),
                stats["packets"],
                unique_ports,
                score_val,
                label
            ]
            log_event(row)
            
            # 5. Handle Threats
            if anomalous or info["flags"]["redirected"]:
                reasons = []
                if anomalous: reasons.append(f"Anomaly ({score_val})")
                if packet_rate > 50: reasons.append("Flood")
                for port in list(stats["ports"])[:3]: reasons.append(f"Port {port}")
                
                threats.append({
                    "ip": ip,
                    "mac": mac,
                    "score": score_val,
                    "trust": new_trust,
                    "flags": info["flags"],
                    "reason": ", ".join(reasons)
                })

        # Dashboard Status Calculation
        status = "ONLINE"
        if is_offline: status = "OFFLINE"
        elif info["flags"]["isolated"]: status = "CONTAINED"
        elif info["flags"]["redirected"]: status = "DECEIVED"
        elif info["flags"]["quarantined"]: status = "NEW/QUARANTINED"
        elif label == 1: status = "SUSPICIOUS"

        active_devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": info.get("hostname", ""),
            "packets": stats["packets"],
            "ports": unique_ports,
            "status": status,
            "trust_score": info["trust_score"], # Exposed to UI
            "last_seen": round(time_since_seen, 1),
            "flags": info["flags"]              # Exposed to UI
        })

    # Reset Cycle
    device_stats = defaultdict(lambda: {"ports": set(), "packets": 0})
    START_TIME = time.time()
    save_devices()
    
    # Correlate threats step moved here to ensure consistency
    if threats:
        from correlation import correlate_threats
        threats = correlate_threats(threats)
        # Apply correlation updates to registry
        for t in threats:
             if "correlation" in t:
                 known_devices[t["mac"]]["trust_score"] = t["trust"]
                 known_devices[t["mac"]]["flags"] = t["flags"]

    return threats, active_devices

def start_ids_cycle(timeout=5):
    try:
        # Sniff packets to gather behavioral stats
        sniff(prn=process_packet, store=False, timeout=timeout)
        return analyze_traffic()
    except Exception as e:
        print(f"[IDS] Error: {e}")
        return [], []
