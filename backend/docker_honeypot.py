import subprocess
import os
import re
import csv
from datetime import datetime

# Configuration
CONTAINER_NAME = "ntth-device"
IMAGE_NAME = "ntth-honeypot:v1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # backend/
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")
HONEYPOT_CSV = os.path.join(DATA_DIR, "honeypot.csv")

# State to avoid duplicate logs
PROCESSED_LINES = 0

def run_cmd(cmd, cwd=None):
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=cwd)
        return True
    except subprocess.CalledProcessError:
        return False

def ensure_image_built():
    """Checks if image exists, builds if not."""
    print("[DOCKER] Checking for honeypot image...")
    # Fix: Use shell=True for strict string commands or list for list commands. Using list for safety.
    check = subprocess.run(["docker", "images", "-q", IMAGE_NAME], capture_output=True, text=True)
    if not check.stdout.strip():
        print(f"[DOCKER] Building {IMAGE_NAME}... This may take a while.")
        if run_cmd(["docker", "build", "-t", IMAGE_NAME, "."], cwd=PROJECT_ROOT):
            print("[DOCKER] Build successful.")
        else:
            print("[DOCKER] Build FAILED. Check Dockerfile.")
            return False
    else:
        print("[DOCKER] Image exists.")
    return True

def start_honeypot():
    """Starts the honeypot container if not running."""
    check = subprocess.run(["docker", "ps", "-q", "-f", f"name={CONTAINER_NAME}"], capture_output=True, text=True)
    if check.stdout.strip():
        print("[DOCKER] Honeypot container already running.")
        return

    # Check if stopped/exited
    check_all = subprocess.run(["docker", "ps", "-aq", "-f", f"name={CONTAINER_NAME}"], capture_output=True, text=True)
    if check_all.stdout.strip():
        print("[DOCKER] Removing stale container...")
        run_cmd(["docker", "rm", "-f", CONTAINER_NAME])

    print("[DOCKER] Starting Honeypot Container...")
    # Map internal ports (2222, 8080, 4445) to Host High Ports
    # We use iptables to redirect 22 -> 2222, etc.
    cmd = [
        "docker", "run", "-d",
        "--name", CONTAINER_NAME,
        "--restart", "always",
        "-p", "2222:2222",
        "-p", "8080:8080",
        "-p", "4445:4445",
        IMAGE_NAME
    ]
    
    if run_cmd(cmd):
        print("[DOCKER] Honeypot started successfully.")
    else:
        print("[DOCKER] Failed to start container.")

def ensure_csv():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(HONEYPOT_CSV):
        with open(HONEYPOT_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            # Schema used by main.py
            writer.writerow(["timestamp", "source_ip", "service", "username", "password", "command", "raw_log"])

def parse_logs():
    """Reads docker logs and appends new entries to CSV."""
    global PROCESSED_LINES
    try:
        # Fetch ALL logs (since start)
        result = subprocess.run(
            ["docker", "logs", CONTAINER_NAME], 
            capture_output=True, text=True, errors="ignore"
        )
        logs = result.stdout.strip().split("\n")
        
        if not logs or logs == ['']:
            return

        total_lines = len(logs)
        if total_lines <= PROCESSED_LINES:
            return # No new logs
            
        new_logs = logs[PROCESSED_LINES:]
        PROCESSED_LINES = total_lines

        ensure_csv()
        
        with open(HONEYPOT_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            
            for line in new_logs:
                if not line.strip(): continue
                
                # Default values
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                src_ip = "unknown"
                service = "unknown"
                username = ""
                password = ""
                command = ""
                
                # --- Log Parsing Logic ---
                
                # 1. Cowrie (SSH/Telnet)
                if "Cowrie" in line:
                    if "CowrieSSH" in line: service = "SSH"
                    elif "CowrieTelnet" in line: service = "Telnet"
                    
                    # Extract IP: [Comp,ID,IP]
                    ip_match = re.search(r"\[.*?,.*?,(.*?)\]", line)
                    if ip_match: src_ip = ip_match.group(1)
                    
                    # Login
                    login_match = re.search(r"login attempt \[(.*?)/(.*?)\]", line)
                    if login_match:
                        username = login_match.group(1)
                        password = login_match.group(2)
                        
                    # Command
                    cmd_match = re.search(r"CMD: (.*)", line)
                    if cmd_match: command = cmd_match.group(1)

                # 2. Dionaea (SMB/FTP/HTTP) or other services if added
                # For now we assume Cowrie is the main noise maker.
                
                # If we detect general traffic not parsed above, try generic extraction
                if src_ip == "unknown":
                    possible_ip = re.search(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", line)
                    if possible_ip: src_ip = possible_ip.group(0)

                # Filter: Only write if it looks interesting
                is_interesting = (username != "") or (command != "") or ("connection" in line)
                
                if is_interesting:
                    writer.writerow([timestamp, src_ip, service, username, password, command, line])

    except Exception as e:
        print(f"[DOCKER] Log parse error: {e}")
