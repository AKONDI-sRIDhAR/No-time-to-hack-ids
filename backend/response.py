import subprocess
import os
import zipfile
import ipaddress
from datetime import datetime

# Configuration
HONEYPOT_SSH = "2222"
HONEYPOT_HTTP = "8080"
HONEYPOT_SMB = "4445"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "data", "iptables_actions.log")

def run_cmd(cmd, ignore_error=False):
    """
    Run shell commands safely.
    Returns True on success, False on failure (if ignored), or raises Exception.
    """
    if os.name == 'nt':
        print(f"[WINDOWS SIMULATION] Executing: {' '.join(cmd)}")
        return True

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            if ignore_error:
                return False
            raise Exception(f"Command failed: {' '.join(cmd)}\nError: {result.stderr.strip()}")
        return True
    except Exception as e:
        if ignore_error:
            print(f"[RESPONSE] Ignored error: {e}")
            return False
        print(f"[RESPONSE] Command execution error: {e}")
        raise

def validate_ip(ip):
    """
    Validates that the input is a valid IPv4 address (not subnet, loopback, or multicast).
    Returns the IP string if valid, else raises ValueError.
    """
    try:
        obj = ipaddress.ip_address(ip)
        if not isinstance(obj, ipaddress.IPv4Address):
            raise ValueError(f"Not an IPv4 address: {ip}")
        if obj.is_loopback:
            raise ValueError(f"Loopback address rejected: {ip}")
        if obj.is_multicast:
            raise ValueError(f"Multicast address rejected: {ip}")
        # Allow private IPs since this is an internal gateway
        return str(obj)
    except ValueError as e:
        raise ValueError(f"Invalid IP address '{ip}': {e}") from e

def log_action(action, details):
    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{t}] {action}: {details}\n"
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(entry)
    except Exception as e:
        print(f"[RESPONSE] Logging failed: {e}")

def _delete_redirect_rule(ip, dport, to_port):
    """
    Deletes a specific DNAT redirect rule in PREROUTING.
    Explicitly targets 'wlan0' interface to intercept incoming traffic.
    """
    # 1. PREROUTING (Incoming on wlan0)
    cmd = [
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-i", "wlan0", "-s", ip, "-p", "tcp", "--dport", str(dport),
        "-j", "REDIRECT", "--to-port", str(to_port)
    ]
    run_cmd(cmd, ignore_error=True)
    
    # 2. OUTPUT (Localhost testing) - Optional but good for verification
    cmd_local = [
        "iptables", "-t", "nat", "-D", "OUTPUT",
        "-s", ip, "-p", "tcp", "--dport", str(dport),
        "-j", "REDIRECT", "--to-port", str(to_port)
    ]
    run_cmd(cmd_local, ignore_error=True)

def _add_redirect_rule(ip, dport, to_port):
    """
    Adds a DNAT redirect rule to intercept attacker traffic.
    MUST bind to interface 'wlan0' to catch traffic traversing the gateway.
    """
    # 1. PREROUTING (Real Attackers via WiFi)
    cmd = [
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-i", "wlan0", "-s", ip, "-p", "tcp", "--dport", str(dport),
        "-j", "REDIRECT", "--to-port", str(to_port)
    ]
    run_cmd(cmd)

def deploy_honeypot(attacker_ip):
    """
    Redirect attacker traffic to Docker Honeypot ports.
    Now correctly targets PREROUTING on wlan0.
    """
    try:
        ip = validate_ip(attacker_ip)
    except ValueError as e:
        print(f"[RESPONSE] Security Reject: {e}")
        return

    print(f"[RESPONSE] Redirecting {ip} to Honeypot Grid")
    log_action("REDIRECT", f"{ip} -> Honeypot Grid (SSH:2222, HTTP:8080, SMB:4445)")

    # Enable forwarding just in case
    run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"], ignore_error=True)

    # SSH -> 2222
    _delete_redirect_rule(ip, 22, HONEYPOT_SSH)
    _add_redirect_rule(ip, 22, HONEYPOT_SSH)
    
    # HTTP -> 80
    _delete_redirect_rule(ip, 80, HONEYPOT_HTTP)
    _add_redirect_rule(ip, 80, HONEYPOT_HTTP)

    # SMB -> 445
    _delete_redirect_rule(ip, 445, HONEYPOT_SMB)
    _add_redirect_rule(ip, 445, HONEYPOT_SMB)

def isolate_attacker(attacker_ip):
    """
    Completely isolate attacker from other devices using Forwarding DROP.
    """
    try:
        ip = validate_ip(attacker_ip)
    except ValueError as e:
        print(f"[RESPONSE] Security Reject: {e}")
        return

    print(f"[RESPONSE] Isolating attacker {ip}")
    log_action("ISOLATE", f"Dropped Traffic for {ip}")

    # Ensure no duplicates
    run_cmd(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], ignore_error=True)
    run_cmd(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], ignore_error=True)

    # Add Drop Rules
    run_cmd(["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"])
    run_cmd(["iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"])
    
    generate_evidence_zip()

def block_mac(mac):
    """
    Permanently block a MAC address using iptables MAC match.
    """
    if not mac or len(mac.split(":")) != 6:
        print(f"[RESPONSE] Invalid MAC for blocking: {mac}")
        return

    print(f"[RESPONSE] BLOCKING MAC {mac}")
    log_action("BLOCK", f"Permanent Block for {mac}")

    # Clean duplicates
    run_cmd(["iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"], ignore_error=True)
    # Add Block
    run_cmd(["iptables", "-A", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"])

def unblock_mac(mac):
    """
    Remove MAC block.
    """
    print(f"[RESPONSE] UNBLOCKING MAC {mac}")
    log_action("UNBLOCK", f"Released {mac}")
    run_cmd(["iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"], ignore_error=True)

def quarantine_device(mac, ip):
    """
    Quarantine Mode:
    1. Redirect HTTP to Decoy (Honeypot)
    2. Rate Limit Forwarding (Slow down scans)
    """
    print(f"[RESPONSE] QUARANTINING {ip} ({mac})")
    log_action("QUARANTINE", f"Rate Limit + Redirect for {ip}")
    
    deploy_honeypot(ip) # Redirects traffic
    
    # Rate Limit
    run_cmd(["iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-m", "limit", "--limit", "5/min", "-j", "ACCEPT"], ignore_error=True)
    run_cmd(["iptables", "-A", "FORWARD", "-m", "mac", "--mac-source", mac, "-m", "limit", "--limit", "5/min", "-j", "ACCEPT"])


def disconnect_device(mac):
    """
    Forcefully deauthenticate a station via hostapd/iw.
    """
    print(f"[RESPONSE] KICKING DEVICE {mac}")
    log_action("KICK", f"Deauthenticated {mac}")
    # iw dev wlan0 station del <MAC>
    run_cmd(["iw", "dev", "wlan0", "station", "del", mac], ignore_error=True)


def lockdown_network():
    """
    Emergency lockdown – block all forwarding except gateway
    """
    print("[RESPONSE] NETWORK LOCKDOWN ACTIVATED")
    log_action("LOCKDOWN", "ALL FORWARDING DROPPED")
    run_cmd(["iptables", "-P", "FORWARD", "DROP"])
    
# Alias
isolate = isolate_attacker

def generate_evidence_zip():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"evidence_{timestamp}.zip"
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    zip_path = os.path.join(data_dir, zip_name)
    try:
        os.makedirs(data_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for f_name in ["behavior.csv", "honeypot.csv", "iptables_actions.log"]:
                f_path = os.path.join(data_dir, f_name)
                if os.path.exists(f_path):
                    zf.write(f_path, arcname=f_name)
        return zip_path
    except Exception:
        return None

def release_attacker(ip, mac=None):
    """
    Clear all penalties for an IP/MAC.
    """
    try:
        ip = validate_ip(ip)
    except ValueError:
        pass # Might be just cleaning up by MAC

    print(f"[RESPONSE] Releasing {ip} / {mac}")
    log_action("RELEASE", f"Clearing rules for {ip}/{mac}")
    
    # IP Rules
    _delete_redirect_rule(ip, 22, HONEYPOT_SSH)
    _delete_redirect_rule(ip, 80, HONEYPOT_HTTP)
    _delete_redirect_rule(ip, 445, HONEYPOT_SMB)
    run_cmd(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], ignore_error=True)
    run_cmd(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], ignore_error=True)
    
    # MAC Rules
    if mac:
        unblock_mac(mac)
        # Remove Rate Limit
        run_cmd(["iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-m", "limit", "--limit", "5/min", "-j", "ACCEPT"], ignore_error=True)
