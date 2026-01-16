from scapy.all import sniff, IP, TCP, Ether
from collections import defaultdict
import time
from ml import is_anomalous, log_event

# Store stats per IP
device_stats = defaultdict(lambda: {"ports": set(), "packets": 0, "mac": "unknown"})
START_TIME = time.time()

def process_packet(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        device_stats[ip]["packets"] += 1
        
        if Ether in pkt:
            device_stats[ip]["mac"] = pkt[Ether].src
            
        if TCP in pkt:
            device_stats[ip]["ports"].add(pkt[TCP].dport)

def analyze_traffic():
    global START_TIME, device_stats
    
    now = time.time()
    duration = now - START_TIME
    if duration < 1: duration = 1
    
    threats = []
    
    for ip, data in device_stats.items():
        packet_rate = data["packets"] / duration
        unique_ports = len(data["ports"])
        port_count = len(data["ports"]) # Same as unique for set, but strictly maybe total ports visited? "port_count" usu means count distinct.
        
        anomalous, score_str = is_anomalous(packet_rate, unique_ports)
        label = 1 if anomalous else 0
        
        # Log to CSV
        # timestamp,ip,mac,packet_rate,port_count,unique_ports,scan_score,label
        row = [
            time.strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            data["mac"],
            round(packet_rate, 2),
            data["packets"], # Using raw packet count as port_count? No, user asked for port_count. I'll use total packets or just duplicate unique.
            unique_ports,
            score_str.split(" ")[0], # Just the numeric part for CSV or keep string? User asked for scan_score.
            label
        ]
        log_event(row)
        
        if anomalous:
            threats.append(ip)
            
    # Snapshot active devices
    active_devices = []
    for ip, data in device_stats.items():
        active_devices.append({
            "ip": ip,
            "mac": data["mac"],
            "packets": data["packets"],
            "ports": len(data["ports"]),
            "status": "SUSPICIOUS" if ip in threats else "ONLINE"
        })

    # Reset stats
    device_stats = defaultdict(lambda: {"ports": set(), "packets": 0, "mac": "unknown"})
    START_TIME = time.time()
    
    return threats, active_devices

def start_ids_cycle(timeout=10):
    """
    Runs one cycle of sniffing and analysis.
    """
    try:
        sniff(prn=process_packet, store=False, timeout=timeout)
        return analyze_traffic()
    except Exception as e:
        print(f"[IDS] Error: {e}")
        return [], []
