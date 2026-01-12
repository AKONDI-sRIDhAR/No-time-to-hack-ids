from scapy.all import sniff, IP, TCP, UDP, ARP
from collections import defaultdict
import time

class NetworkWatcher:
    def __init__(self):
        self.devices = defaultdict(lambda: {
            "mac": None,
            "packet_count": 0,
            "ports": set(),
            "last_seen": time.time()
        })

    def packet_handler(self, pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            self.devices[ip]["mac"] = mac

        if IP in pkt:
            ip = pkt[IP].src
            self.devices[ip]["packet_count"] += 1
            self.devices[ip]["last_seen"] = time.time()

            if TCP in pkt:
                self.devices[ip]["ports"].add(pkt[TCP].dport)
            if UDP in pkt:
                self.devices[ip]["ports"].add(pkt[UDP].dport)

    def start(self):
        sniff(iface="wlan0", prn=self.packet_handler, store=False)

    def get_snapshot(self):
        snapshot = {}
        for ip, data in self.devices.items():
            snapshot[ip] = {
                "mac": data["mac"],
                "packet_count": data["packet_count"],
                "ports_touched": len(data["ports"]),
                "last_seen": int(time.time() - data["last_seen"])
            }
        return snapshot
