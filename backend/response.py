import subprocess
import time

HONEYPOT_PORT = "8080"

def run_cmd(cmd):
    """
    Run shell commands safely
    """
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def deploy_honeypot(attacker_ip):
    """
    Redirect ALL attacker TCP traffic to honeypot port 8080
    """
    print(f"[RESPONSE] Redirecting {attacker_ip} to honeypot")

    run_cmd([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", attacker_ip,
        "-p", "tcp",
        "--dport", "1:65535",
        "-j", "REDIRECT",
        "--to-port", HONEYPOT_PORT
    ])

def isolate_attacker(attacker_ip):
    """
    Completely isolate attacker from other devices
    """
    print(f"[RESPONSE] Isolating attacker {attacker_ip}")

    run_cmd(["iptables", "-A", "FORWARD", "-s", attacker_ip, "-j", "DROP"])
    run_cmd(["iptables", "-A", "FORWARD", "-d", attacker_ip, "-j", "DROP"])

def lockdown_network():
    """
    Emergency lockdown – block all forwarding except gateway
    """
    print("[RESPONSE] NETWORK LOCKDOWN ACTIVATED")

    run_cmd(["iptables", "-P", "FORWARD", "DROP"])
