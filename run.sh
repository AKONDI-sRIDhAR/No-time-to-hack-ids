#!/bin/bash
set -e

echo "========================================="
echo " NO TIME TO HACK :: AUTONOMOUS IDS START "
echo "========================================="

# ---- SAFETY CHECK ----
if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root: sudo ./run.sh"
  exit 1
fi

BASE_DIR=$(pwd)

# ---- 1. ENSURE DOCKER IS RUNNING ----
echo "[+] Checking Docker service..."
if ! systemctl is-active --quiet docker; then
    echo "[!] Docker not running. Starting..."
    systemctl start docker
    sleep 3
fi
echo "[✓] Docker is running"

# ---- 2. VERIFY HONEYPOT CONTAINERS ----
echo "[+] Verifying deception layer..."

REQUIRED_CONTAINERS=("ntth-device" "http-hp" "smb-honeypot")
MISSING=0

for c in "${REQUIRED_CONTAINERS[@]}"; do
    if docker ps --format '{{.Names}}' | grep -q "^$c$"; then
        echo "[✓] $c is running"
    else
        echo "[-] $c is NOT running"
        MISSING=1
    fi
done

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "[-] Deception layer incomplete."
    echo "[-] Start honeypots FIRST, then rerun ./run.sh"
    exit 1
fi

echo "[✓] All honeypots active"

# ---- 3. START IDS BACKEND (AI BRAIN) ----
echo "[+] Starting IDS brain..."
cd "$BASE_DIR/backend"

# ---- VIRTUAL ENV FIX (THIS IS THE KEY PART) ----
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "[+] Ensuring Python dependencies..."
pip install --quiet flask flask-cors

# Dataset
mkdir -p data
IDS_CSV="data/behavior.csv"

if [ ! -f "$IDS_CSV" ]; then
  echo "timestamp,ip,mac,packet_rate,port_count,unique_ports,scan_score,label" > "$IDS_CSV"
  echo "[+] Created IDS dataset"
fi

# IMPORTANT: use `python`, not `python3`
export FLASK_ENC=production
python main.py &
IDS_PID=$!

# ---- 4. START DASHBOARD ----
echo "[+] Starting dashboard..."
cd "$BASE_DIR/frontend"
python3 -m http.server 5050 >/dev/null 2>&1 &
UI_PID=$!

# ---- STATUS ----
echo ""
echo "========================================="
echo " SYSTEM STATUS: LIVE"
echo "-----------------------------------------"
echo " Gateway IP      : 192.168.10.1"
echo " Dashboard       : http://192.168.10.1:5050"
echo " SSH Honeypot    : 2222 (Cowrie)"
echo " HTTP Decoy      : 8080"
echo " SMB Honeypot    : 445"
echo " IDS Dataset     : backend/data/behavior.csv"
echo "========================================="
echo ""

wait $IDS_PID
