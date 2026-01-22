from scapy.all import sniff, IP, TCP, Ether
from collections import defaultdict
import time
import subprocess
import os
from ml import is_anomalous, log_event

DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"
INTERFACE = "wlan0"

device_stats = defaultdict(lambda: {"ports": set(), "packets": 0, "mac": "unknown"})
START_TIME = time.time()

def get_ap_devices():
    devices = {}

    if os.path.exists(DNSMASQ_LEASES):
        with open(DNSMASQ_LEASES, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[2]
                    mac = parts[1]
                    hostname = parts[3]
                    devices[ip] = {
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                        "state": "CONNECTED"
                    }

    try:
        arp = subprocess.check_output(
            ["ip", "neigh", "show", "dev", INTERFACE],
            stderr=subprocess.DEVNULL
        ).decode()

        for line in arp.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                state = parts[-1]
                if ip in devices:
                    devices[ip]["state"] = state
    except Exception:
        pass

    return devices

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
    duration = max(now - START_TIME, 1)

    ap_devices = get_ap_devices()
    threats = []
    active_devices = []

    for ip, ap_data in ap_devices.items():
        stats = device_stats.get(ip, {"ports": set(), "packets": 0, "mac": ap_data["mac"]})

        packet_rate = stats["packets"] / duration
        unique_ports = len(stats["ports"])
        port_count = unique_ports

        anomalous, score_str = is_anomalous(packet_rate, unique_ports)
        label = 1 if anomalous else 0

        row = [
            time.strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            ap_data["mac"],
            round(packet_rate, 2),
            port_count,
            unique_ports,
            score_str.split(" ")[0],
            label
        ]
        log_event(row)

        if anomalous:
            threats.append(ip)

        active_devices.append({
            "ip": ip,
            "mac": ap_data["mac"],
            "hostname": ap_data.get("hostname", ""),
            "state": ap_data.get("state", ""),
            "packets": stats["packets"],
            "ports": unique_ports,
            "status": "SUSPICIOUS" if anomalous else "ONLINE"
        })

    device_stats = defaultdict(lambda: {"ports": set(), "packets": 0, "mac": "unknown"})
    START_TIME = time.time()

    return threats, active_devices

def start_ids_cycle(timeout=5):
    try:
        sniff(prn=process_packet, store=False, timeout=timeout)
        return analyze_traffic()
    except Exception as e:
        print(f"[IDS] Error: {e}")
        return [], []
