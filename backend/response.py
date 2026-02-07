import subprocess
import os
import zipfile
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
    """
    if os.name == 'nt':
        print(f"[WINDOWS SIMULATION] Executing: {' '.join(cmd)}")
        return

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 and not ignore_error:
            print(f"[RESPONSE] Command failed: {' '.join(cmd)}\nError: {result.stderr.strip()}")
    except Exception as e:
        print(f"[RESPONSE] Command execution error: {e}")

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
    # Try to delete rule if it exists
    cmd = [
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-s", ip, "-p", "tcp", "--dport", str(dport),
        "-j", "REDIRECT", "--to-port", str(to_port)
    ]
    run_cmd(cmd, ignore_error=True)

def _add_redirect_rule(ip, dport, to_port):
    cmd = [
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", ip, "-p", "tcp", "--dport", str(dport),
        "-j", "REDIRECT", "--to-port", str(to_port)
    ]
    run_cmd(cmd)

def deploy_honeypot(attacker_ip):
    """
    Redirect attacker traffic to Docker Honeypot ports
    """
    print(f"[RESPONSE] Redirecting {attacker_ip} to Honeypot Grid")
    log_action("REDIRECT", f"{attacker_ip} -> Honeypot Grid (SSH:2222, HTTP:8080, SMB:4445)")

    # SSH -> 2222
    _delete_redirect_rule(attacker_ip, 22, HONEYPOT_SSH)
    _add_redirect_rule(attacker_ip, 22, HONEYPOT_SSH)
    
    # HTTP -> 8080
    _delete_redirect_rule(attacker_ip, 80, HONEYPOT_HTTP)
    _add_redirect_rule(attacker_ip, 80, HONEYPOT_HTTP)

    # SMB -> 4445
    _delete_redirect_rule(attacker_ip, 445, HONEYPOT_SMB)
    _add_redirect_rule(attacker_ip, 445, HONEYPOT_SMB)

def isolate_attacker(attacker_ip):
    """
    Completely isolate attacker from other devices
    """
    print(f"[RESPONSE] Isolating attacker {attacker_ip}")
    log_action("ISOLATE", f"Dropped Traffic for {attacker_ip}")

    # Ensure no duplicates by deleting first
    run_cmd(["iptables", "-D", "FORWARD", "-s", attacker_ip, "-j", "DROP"], ignore_error=True)
    run_cmd(["iptables", "-D", "FORWARD", "-d", attacker_ip, "-j", "DROP"], ignore_error=True)

    run_cmd(["iptables", "-A", "FORWARD", "-s", attacker_ip, "-j", "DROP"])
    run_cmd(["iptables", "-A", "FORWARD", "-d", attacker_ip, "-j", "DROP"])
    
    generate_evidence_zip()

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
    """
    Archives behavior and honeypot logs into a ZIP file.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"evidence_{timestamp}.zip"
    
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    zip_path = os.path.join(data_dir, zip_name)
    
    try:
        os.makedirs(data_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'w') as zf:
            # Add files if they exist
            for f_name in ["behavior.csv", "honeypot.csv", "iptables_actions.log"]:
                f_path = os.path.join(data_dir, f_name)
                if os.path.exists(f_path):
                    zf.write(f_path, arcname=f_name)
        print(f"[RESPONSE] Evidence generated: {zip_path}")
        return zip_path
    except Exception as e:
        print(f"[RESPONSE] Evidence generation failed: {e}")
        return None

def release_attacker(ip):
    """
    Remove isolation and redirection rules for an IP.
    """
    print(f"[RESPONSE] Releasing {ip}")
    log_action("RELEASE", f"Clearing rules for {ip}")
    
    # Delete Redirects
    _delete_redirect_rule(ip, 22, HONEYPOT_SSH)
    _delete_redirect_rule(ip, 80, HONEYPOT_HTTP)
    _delete_redirect_rule(ip, 445, HONEYPOT_SMB)
    
    # Delete Drops
    run_cmd(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], ignore_error=True)
    run_cmd(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], ignore_error=True)
