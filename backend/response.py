import subprocess
import os

HONEYPOT_SSH = "2222"
HONEYPOT_HTTP = "8080"
HONEYPOT_SMB = "4445"

def run_cmd(cmd):
    """
    Run shell commands safely, ignoring errors on Windows.
    """
    if os.name == 'nt':
        print(f"[WINDOWS SIMULATION] Executing: {' '.join(cmd)}")
        return

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[RESPONSE] Command failed: {e}")

def deploy_honeypot(attacker_ip):
    """
    Redirect attacker traffic to Docker Honeypot ports
    """
    print(f"[RESPONSE] Redirecting {attacker_ip} to Honeypot Grid")

    # SSH -> 2222
    run_cmd([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", attacker_ip, "-p", "tcp", "--dport", "22",
        "-j", "REDIRECT", "--to-port", HONEYPOT_SSH
    ])
    
    # HTTP -> 8080
    run_cmd([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", attacker_ip, "-p", "tcp", "--dport", "80",
        "-j", "REDIRECT", "--to-port", HONEYPOT_HTTP
    ])

    # SMB -> 4445
    run_cmd([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", attacker_ip, "-p", "tcp", "--dport", "445",
        "-j", "REDIRECT", "--to-port", HONEYPOT_SMB
    ])
    
    # Catch-all? Redirect other high ports to HTTP?
    # For now, we only trap specific services to limit noise.

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
    
# Alias
isolate = isolate_attacker

def release_attacker(ip):
    """
    Remove isolation and redirection rules for an IP.
    """
    print(f"[RESPONSE] Releasing {ip}")
    # Delete Redirects
    run_cmd(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "22", "-j", "REDIRECT", "--to-port", HONEYPOT_SSH])
    run_cmd(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", HONEYPOT_HTTP])
    run_cmd(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "445", "-j", "REDIRECT", "--to-port", HONEYPOT_SMB])
    
    # Delete Drops
    run_cmd(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    run_cmd(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"])
