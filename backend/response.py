import os

def isolate(ip):
    os.system(f"iptables -A FORWARD -s {ip} -j DROP")
