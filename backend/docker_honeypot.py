import subprocess
import os
import re
import csv
import json
from datetime import datetime

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
HONEYPOT_CSV = os.path.join(DATA_DIR, "honeypot.csv")

# Containers
CONTAINERS = {
    "SSH": {"name": "ntth-device", "image": "ntth-honeypot:v1", "ports": ["2222:2222"]},
    "HTTP": {"name": "http-hp", "image": "nginx:alpine", "ports": ["8080:80"]},
    "SMB": {"name": "smb-honeypot", "image": "dinotools/dionaea", "ports": ["4445:445"]}
}

# State to avoid duplicate logs (per container)
PROCESSED_LINES = {
    "ntth-device": 0,
    "http-hp": 0,
    "smb-honeypot": 0
}

def run_cmd(cmd):
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def ensure_image(image):
    check = subprocess.run(["docker", "images", "-q", image], capture_output=True, text=True)
    if not check.stdout.strip():
        print(f"[DOCKER] Pulling/Building {image}...")
        if "ntth-honeypot" in image:
            # Build local
            root = os.path.dirname(BASE_DIR)
            subprocess.run(["docker", "build", "-t", image, "."], cwd=root)
        else:
            # Pull remote
            run_cmd(["docker", "pull", image])

def start_container(key, cfg):
    name = cfg["name"]
    check = subprocess.run(["docker", "ps", "-q", "-f", f"name={name}"], capture_output=True, text=True)
    if check.stdout.strip():
        return # Already running

    # Remove stale
    run_cmd(["docker", "rm", "-f", name])
    
    ensure_image(cfg["image"])
    
    cmd = ["docker", "run", "-d", "--name", name, "--restart", "always"]
    for p in cfg["ports"]:
        cmd.extend(["-p", p])
    cmd.append(cfg["image"])
    
    if run_cmd(cmd):
        print(f"[DOCKER] Started {name} for {key}")
    else:
        print(f"[DOCKER] Failed to start {name}")

def start_honeypot():
    print("[DOCKER] Initializing Deception Grid...")
    for key, cfg in CONTAINERS.items():
        start_container(key, cfg)

def ensure_csv():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(HONEYPOT_CSV):
        with open(HONEYPOT_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            # Schema: timestamp, ip, service, username, password, metadata
            writer.writerow(["timestamp", "source_ip", "service", "username", "password", "metadata"])

def parse_logs():
    global PROCESSED_LINES
    ensure_csv()
    
    for key, cfg in CONTAINERS.items():
        name = cfg["name"]
        try:
            result = subprocess.run(
                ["docker", "logs", name], 
                capture_output=True, text=True, errors="ignore"
            )
            logs = result.stdout.strip().split("\n")
            if not logs or logs == ['']: continue
            
            last_idx = PROCESSED_LINES.get(name, 0)
            if len(logs) <= last_idx: continue
            
            new_logs = logs[last_idx:]
            PROCESSED_LINES[name] = len(logs)
            
            with open(HONEYPOT_CSV, "a", newline="") as f:
                writer = csv.writer(f)
                for line in new_logs:
                    if not line.strip(): continue
                    process_log_line(key, line, writer)
                    
        except Exception:
            pass

def process_log_line(service, line, writer):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = "unknown"
    user = ""
    pwd = ""
    meta = ""
    
    # --- Cowrie (SSH) ---
    if service == "SSH":
        # Try JSON first
        try:
            data = json.loads(line)
            ip = data.get("src_ip", "unknown")
            user = data.get("username", "")
            pwd = data.get("password", "")
            meta = data.get("eventid", "")
            if data.get("eventid") == "cowrie.command.input":
                meta = f"CMD: {data.get('input', '')}"
        except json.JSONDecodeError:
            # Fallback to regex
            m = re.search(r"src_ip=([^ ]+)", line)
            if not m:
                m = re.search(r"\[.*?,.*?,(.*?)\]", line)
            if m:
                ip = m.group(1)

            m = re.search(r"login attempt \[(.*?)/(.*?)\]", line)
            if m:
                user = m.group(1)
                pwd = m.group(2)
                meta = "SSH Login Attempt"

            if "CMD:" in line:
                meta = line.split("CMD:")[-1].strip()

    # --- Nginx (HTTP) ---
    elif service == "HTTP":
        # Standard combined format: IP - - [date] "REQ" status bytes "ref" "ua"
        parts = line.split(" ")
        if len(parts) > 0:
            ip = parts[0]
            if "HTTP" in line:
                # Extract Request
                m = re.search(r"\"(.*?)\"", line)
                if m: meta = m.group(1)
            # Extract UA
            m = re.search(r"\"(.*?)\"$", line)
            if m:
                ua = m.group(1)
                meta += f" | UA: {ua[:20]}..."

    # --- Dionaea (SMB) ---
    elif service == "SMB":
        # Generic capture
        m = re.search(r"Connection from (.*?) ", line)
        if m: ip = m.group(1)
        meta = line[:50] # Raw snippet

    # Only write if interesting or we have IP
    if ip != "unknown" or user or meta:
        # Schema: timestamp, ip, service, username, password, metadata
        writer.writerow([ts, ip, service, user, pwd, meta.replace(",", ";")])
