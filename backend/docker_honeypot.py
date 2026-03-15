import csv
import json
import os
import re
import subprocess
from datetime import datetime

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
HONEYPOT_CSV = os.path.join(DATA_DIR, "honeypot.csv")
GRID_NAME = "ntth-grid"
GRID_IMAGE = "ntth-honeypot:v1"
GRID_PORTS = ["2222:2222", "8080:8080", "445:445"]

PROCESSED_LINES = 0


def run_cmd(cmd):
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def ensure_image():
    check = subprocess.run(["docker", "images", "-q", GRID_IMAGE], capture_output=True, text=True)
    if check.stdout.strip():
        return

    print(f"[DOCKER] Building {GRID_IMAGE} locally...")
    root = os.path.dirname(BASE_DIR)
    subprocess.run(["docker", "build", "-t", GRID_IMAGE, "."], cwd=root, check=True)


def start_honeypot():
    print("[DOCKER] Initializing Deception Grid...")
    check = subprocess.run(["docker", "ps", "-q", "-f", f"name={GRID_NAME}"], capture_output=True, text=True)
    if check.stdout.strip():
        return

    run_cmd(["docker", "rm", "-f", GRID_NAME])
    ensure_image()

    cmd = ["docker", "run", "-d", "--name", GRID_NAME, "--restart", "always"]
    for port in GRID_PORTS:
        cmd.extend(["-p", port])
    cmd.append(GRID_IMAGE)

    if run_cmd(cmd):
        print(f"[DOCKER] Started {GRID_NAME}")
    else:
        print(f"[DOCKER] Failed to start {GRID_NAME}")


def ensure_csv():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(HONEYPOT_CSV):
        with open(HONEYPOT_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "source_ip", "service", "username", "password", "metadata"])


def parse_logs():
    global PROCESSED_LINES
    ensure_csv()

    try:
        result = subprocess.run(
            ["docker", "logs", GRID_NAME],
            capture_output=True,
            text=True,
            errors="ignore",
        )
        logs = result.stdout.strip().splitlines()
        if not logs:
            return

        if len(logs) <= PROCESSED_LINES:
            return

        new_logs = logs[PROCESSED_LINES:]
        PROCESSED_LINES = len(logs)

        with open(HONEYPOT_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            for line in new_logs:
                process_log_line(line, writer)
    except Exception:
        pass


def _write_row(writer, service, ip, user="", pwd="", meta=""):
    if ip == "unknown" and not user and not meta:
        return

    writer.writerow(
        [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            service,
            user,
            pwd,
            str(meta).replace(",", ";"),
        ]
    )


def _process_json_log(data, writer):
    service = data.get("service", "")
    eventid = data.get("eventid", "")
    ip = data.get("src_ip", "unknown")

    if service == "HTTP":
        user = data.get("username", "")
        pwd = data.get("password", "")
        meta = eventid
        if data.get("path"):
            meta = f"{meta} {data.get('path')}".strip()
        if data.get("user_agent"):
            meta = f"{meta} | UA: {data.get('user_agent', '')[:40]}"
        _write_row(writer, "HTTP", ip, user, pwd, meta)
        return

    user = data.get("username", "")
    pwd = data.get("password", "")
    meta = eventid
    if eventid == "cowrie.command.input":
        meta = f"CMD: {data.get('input', '')}"
    _write_row(writer, "SSH", ip, user, pwd, meta)


def _process_smb_line(line, writer):
    line = line.replace("[SMB]", "", 1).strip()
    ip = "unknown"
    user = ""
    pwd = ""
    meta = line[:120]

    match = re.search(r"from ipv4:([0-9.]+):", line)
    if match:
        ip = match.group(1)

    if "authentication for user" in line.lower():
        match = re.search(r"user\s+\[([^\]]+)\]", line, re.IGNORECASE)
        if match:
            user = match.group(1)

    _write_row(writer, "SMB", ip, user, pwd, meta)


def _process_plain_ssh_line(line, writer):
    ip = "unknown"
    user = ""
    pwd = ""
    meta = ""

    match = re.search(r"src_ip=([^ ]+)", line)
    if match:
        ip = match.group(1)

    match = re.search(r"login attempt \[(.*?)/(.*?)\]", line)
    if match:
        user = match.group(1)
        pwd = match.group(2)
        meta = "SSH Login Attempt"

    if "CMD:" in line:
        meta = line.split("CMD:", 1)[1].strip()

    _write_row(writer, "SSH", ip, user, pwd, meta or line[:120])


def process_log_line(line, writer):
    if not line.strip():
        return

    if line.lstrip().startswith("{"):
        try:
            _process_json_log(json.loads(line), writer)
            return
        except json.JSONDecodeError:
            pass

    if line.startswith("[SMB]"):
        _process_smb_line(line, writer)
        return

    _process_plain_ssh_line(line, writer)
