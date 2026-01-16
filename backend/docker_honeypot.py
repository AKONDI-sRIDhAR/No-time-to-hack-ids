import subprocess
import time
import os
import json
import re
import csv
from datetime import datetime

# Configuration
CONTAINER_NAME = "ntth-device"
IMAGE_NAME = "ntth-honeypot:v1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # backend/
PROJECT_ROOT = os.path.dirname(BASE_DIR)
HONEYPOT_CSV = os.path.join(BASE_DIR, "data", "honeypot.csv")

# Port Mapping (Host -> Container)
# We assume the container listens on 2222, 8080, 4445 internally
# We map them to High Ports on Host so we can redirect via iptables
PORTS = {
    "2222": "2222",
    "8080": "8080",
    "4445": "4445"
}

def run_cmd(cmd, cwd=None):
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=cwd)
        return True
    except subprocess.CalledProcessError:
        return False

def ensure_image_built():
    """Checks if image exists, builds if not."""
    print("[DOCKER] Checking for honeypot image...")
    check = subprocess.run(["docker", "images", "-q", IMAGE_NAME], capture_output=True, text=True)
    if not check.stdout.strip():
        print(f"[DOCKER] Building {IMAGE_NAME}... This may take a while.")
        # Build from Project Root where Dockerfile is located
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
    # Check if running
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

def stop_honeypot():
    run_cmd(["docker", "rm", "-f", CONTAINER_NAME])

def ensure_csv():
    os.makedirs(os.path.dirname(HONEYPOT_CSV), exist_ok=True)
    if not os.path.exists(HONEYPOT_CSV):
        with open(HONEYPOT_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "source_ip", "service", "username", "password", "command", "raw_log"])

# State
PROCESSED_LINES = 0

def parse_logs():
    """Reads docker logs and appends new entries to CSV."""
    global PROCESSED_LINES
    try:
        # Fetch ALL logs (since start) - efficient enough for prototype
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
                
                # Cowrie Format (JSON if configured, otherwise text)
                # Text example: "2023-01-01T12:00:00+0000 [CowrieTelnetTransport,10,192.168.1.5] login attempt [root/123456] succeeded"
                
                # Check line format
                # Extract IP (Rough regex for [Transport,Id,IP])
                ip_match = re.search(r"\[.*?,.*?,(.*?)\]", line)
                if ip_match:
                    src_ip = ip_match.group(1)
                
                # Detect Service
                if "CowrieSSH" in line: service = "SSH"
                elif "CowrieTelnet" in line: service = "Telnet"
                elif "http" in line.lower(): service = "HTTP"
                elif "smb" in line.lower(): service = "SMB"
                else: service = "Honeypot" # Fallback
                
                # Login Attempts
                if "login attempt" in line:
                    creds_match = re.search(r"\[(.*?)/(.*?)\]", line)
                    if creds_match:
                        username = creds_match.group(1)
                        password = creds_match.group(2)
                
                # Commands
                cmd_match = re.search(r"CMD: (.*)", line)
                if cmd_match:
                    command = cmd_match.group(1)

                # Filter: Only log interesting events
                if "login attempt" in line or "CMD:" in line or "connection" in line:
                    writer.writerow([timestamp, src_ip, service, username, password, command, line])

    except Exception as e:
        print(f"[DOCKER] Log parse error: {e}")

