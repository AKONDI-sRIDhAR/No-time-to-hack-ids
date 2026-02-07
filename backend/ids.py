from scapy.all import sniff, IP, TCP, Ether, ARP
from collections import defaultdict
import time
import subprocess
import os
import json
import threading
from ml import is_anomalous, log_event

# Configuration
OFFLINE_THRESHOLD = 30  # seconds inactive -> OFFLINE
DEVICES_FILE = "backend/data/devices.json"

# Persistent Registry
known_devices = {}
lock = threading.RLock() # Thread-safety for Flask API vs Background Loop

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
    """Persist registry to disk safely."""
    with lock:
        os.makedirs(os.path.dirname(DEVICES_FILE), exist_ok=True)
        with open(DEVICES_FILE, "w") as f:
            json.dump(known_devices, f, indent=4)

known_devices = load_devices()

def get_dhcp_leases():
    """
    Parses dnsmasq leases for authoritative device info.
    Format: expiry_time mac ip hostname clientid
    """
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
            now = time.time()
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            expiry = float(parts[0])
                            mac = parts[1]
                            ip = parts[2]
                            hostname = parts[3] if len(parts) > 3 else "unknown"

                            # ONLY return valid leases
                            if expiry > now:
                                leases[mac] = {
                                    "ip": ip,
                                    "hostname": hostname,
                                    "expiry": expiry
                                }
                        except ValueError:
                            continue
        except Exception as e:
            print(f"[IDS] DHCP Parse Error: {e}")
    return leases

def get_arp_table():
    """Parses system ARP table."""
    arp_entries = {}
    try:
        output = subprocess.check_output(["ip", "neigh"], text=True)
        for line in output.splitlines():
            parts = line.split()
            # 192.168.10.x dev wlan0 lladdr AA:BB:CC... STALE/REACHABLE
            if "lladdr" in parts:
                try:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        mac = parts[idx + 1]
                        ip = parts[0]
                        state = parts[-1]
                        if state not in ["FAILED", "INCOMPLETE"]:
                            arp_entries[mac] = ip
                except ValueError:
                    continue
    except Exception as e:
        print(f"[IDS] ARP Scan Failed: {e}")
        pass
    return arp_entries

def get_wifi_associations():
    """
    Parses 'iw dev wlan0 station dump' for strictly associated clients.
    This confirms physical presence even if silent on IP layer.
    """
    associated_macs = set()
    try:
        # Assuming wlan0 is the AP interface. 
        # In a real environment we might want to detect this dynamically or config it.
        # But 'wlan0' is standard for this project context (apmode.sh).
        output = subprocess.check_output(["iw", "dev", "wlan0", "station", "dump"], text=True)
        for line in output.splitlines():
            if "Station" in line:
                # Format: Station AA:BB:CC:DD:EE:FF (on wlan0)
                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[1]
                    associated_macs.add(mac)
    except Exception as e:
        print(f"[IDS] WiFi Dump Failed: {e}")
        pass
    return associated_macs

def scan_network_state():
    """
    Updates known_devices Registry.
    Authoritative Presence Logic (The "Trinity"):
    1. DHCP: Identity Source (Hostname, IP, Lease)
    2. ARP:  Layer 3 Heartbeat (Actively communicating)
    3. Wi-Fi: Layer 2 Presence (Physically connected)
    
    If ANY of these say "Here", the device is ONLINE.
    """
    global known_devices
    now = time.time()
    
    dhcp = get_dhcp_leases()
    arp = get_arp_table()
    wifi_clients = get_wifi_associations()
    
    with lock:
        # 1. Process DHCP (Identity + Presence)
        for mac, info in dhcp.items():
            if mac not in known_devices:
                known_devices[mac] = {
                    "ip": info["ip"],
                    "hostname": info["hostname"],
                    "mac": mac,
                    "first_seen": now,
                    "last_seen": now, 
                    "trust_score": 50,
                    "flags": {"redirected": False, "isolated": False, "quarantined": True}
                }
            else:
                known_devices[mac]["ip"] = info["ip"]
                if info["hostname"] != "unknown":
                    known_devices[mac]["hostname"] = info["hostname"]
                
                # Valid lease = Presumed Online
                known_devices[mac]["last_seen"] = now

        # 2. Process ARP (Real-time Heartbeat)
        for mac, ip in arp.items():
            if mac not in known_devices:
                known_devices[mac] = {
                    "ip": ip,
                    "hostname": "unknown",
                    "mac": mac,
                    "first_seen": now,
                    "last_seen": now,
                    "trust_score": 50,
                    "flags": {"redirected": False, "isolated": False, "quarantined": True}
                }
            
            known_devices[mac]["last_seen"] = now
            known_devices[mac]["ip"] = ip 
            
        # 3. Process Wi-Fi Association (Physical Presence)
        for mac in wifi_clients:
            if mac in known_devices:
                 known_devices[mac]["last_seen"] = now
            else:
                # Connected to Wifi but no IP yet?
                known_devices[mac] = {
                    "ip": "0.0.0.0",
                    "hostname": "unknown",
                    "mac": mac,
                    "first_seen": now,
                    "last_seen": now,
                    "trust_score": 50,
                    "flags": {"redirected": False, "isolated": False, "quarantined": True}
                }
        
def process_packet(pkt):
    global device_stats
    if Ether in pkt:
        mac = pkt[Ether].src
        # Traffic maps to behavior stats but does NOT confirm presence
        device_stats[mac]["packets"] += 1
        if TCP in pkt:
            device_stats[mac]["ports"].add(pkt[TCP].dport)

def update_trust_score(info, anomalous, packet_rate, unique_ports):
    score = info.get("trust_score", 50)
    if anomalous: score -= 20
    if unique_ports > 10: score -= 10
    if packet_rate > 50: score -= 5
    if not anomalous and unique_ports < 5: score += 1
    return max(0, min(100, score))

def analyze_traffic():
    global START_TIME, device_stats
    
    # Lock the entire analysis phase to prevent partial reads/writes
    with lock:
        # PRESENCE IS DETERMINED HERE ONLY (The "Trinity")
        scan_network_state()
        
        now = time.time()
        duration = max(now - START_TIME, 1)
        
        threats = []
        active_devices = []

        for mac, info in known_devices.items():
            ip = info.get("ip", "0.0.0.0")
            stats = device_stats.get(mac, {"ports": set(), "packets": 0})
            
            # Traffic is analyzed for BEHAVIOR, but ignored for PRESENCE.
            # "last_seen" is NOT updated here.
            
            time_since_seen = now - info["last_seen"]
            is_offline = time_since_seen > OFFLINE_THRESHOLD
            
            packet_rate = stats["packets"] / duration
            unique_ports = len(stats["ports"])
            
            label = 0
            score_val = 0
            
            if not is_offline:
                anomalous, score_str = is_anomalous(packet_rate, unique_ports)
                try:
                    score_val = int(score_str.split(" ")[0])
                except:
                    score_val = 0
                label = 1 if anomalous else 0

                new_trust = update_trust_score(info, anomalous, packet_rate, unique_ports)
                known_devices[mac]["trust_score"] = new_trust
                
                if info["flags"]["quarantined"] and new_trust > 70 and (now - info["first_seen"] > 60):
                    known_devices[mac]["flags"]["quarantined"] = False
                
                if new_trust < 40: known_devices[mac]["flags"]["redirected"] = True
                if new_trust < 20: known_devices[mac]["flags"]["isolated"] = True

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

            status = "ONLINE"
            if is_offline:
                status = "OFFLINE"
            elif info["flags"]["isolated"]:
                status = "CONTAINED"
            elif info["flags"]["redirected"]:
                status = "DECEIVED"
            elif info["flags"]["quarantined"]:
                status = "NEW/QUARANTINED"
            elif label == 1:
                status = "SUSPICIOUS"
            elif stats["packets"] == 0:
                status = "IDLE"

            active_devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": info.get("hostname", ""),
                "packets": stats["packets"],
                "ports": unique_ports,
                "status": status,
                "trust_score": info.get("trust_score", 50),
                "last_seen": round(time_since_seen, 1),
                "flags": info["flags"]
            })

        device_stats = defaultdict(lambda: {"ports": set(), "packets": 0})
        START_TIME = time.time()
        save_devices()
        
        try:
            if threats:
                from correlation import correlate_threats
                threats = correlate_threats(threats)
                for t in threats:
                     if "correlation" in t:
                         if t["mac"] in known_devices:
                             known_devices[t["mac"]]["trust_score"] = t["trust"]
                             known_devices[t["mac"]]["flags"] = t["flags"]
        except ImportError:
            pass

        return threats, active_devices

def start_ids_cycle(timeout=5):
    try:
        sniff(prn=process_packet, store=False, timeout=timeout)
        return analyze_traffic()
    except Exception as e:
        print(f"[IDS] Error: {e}")
        return [], []
