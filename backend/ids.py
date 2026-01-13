from scapy.all import sniff, IP, TCP
from ml import score

alerts = []

def analyze(pkt):
    if IP in pkt and TCP in pkt:
        src = pkt[IP].src
        dport = pkt[TCP].dport
        threat = score(20, dport)

        if threat == "HIGH":
            alerts.append({
                "source": src,
                "port": dport,
                "level": "CRITICAL"
            })

def start_ids():
    sniff(prn=analyze, store=False, iface="wlan0")
