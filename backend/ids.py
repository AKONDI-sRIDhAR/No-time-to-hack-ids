from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
from ml import is_anomalous, log_event

device_stats = defaultdict(lambda: {"ports": set(), "packets": 0})
START = time.time()

def process_packet(pkt):
    if IP in pkt and TCP in pkt:
        ip = pkt[IP].src
        device_stats[ip]["packets"] += 1
        device_stats[ip]["ports"].add(pkt[TCP].dport)

def analyze():
    now = time.time()
    for ip, data in device_stats.items():
        duration = max(now - START, 1)
        packet_rate = data["packets"] / duration
        unique_ports = len(data["ports"])

        anomalous, score = is_anomalous(packet_rate, unique_ports)
        label = "suspicious" if anomalous else "normal"

        log_event([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            "unknown",
            round(packet_rate,2),
            data["packets"],
            unique_ports,
            score,
            label
        ])

        if anomalous:
            return ip
    return None

def start_ids():
    sniff(prn=process_packet, store=False, timeout=10)
    return analyze()
