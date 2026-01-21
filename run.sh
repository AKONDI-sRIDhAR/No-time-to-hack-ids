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

# ---- 2. ENSURE HONEYPOT IMAGE EXISTS ----
if ! docker images | grep -q ntth-honeypot; then
    echo "[-] Honeypot image not found. Build it first:"
    echo "    docker build -t ntth-honeypot:v1 ."
    exit 1
fi

# ---- 3. START / RESTART HONEYPOT CONTAINER ----
echo "[+] Deploying deception honeypot..."
docker rm -f ntth-device >/dev/null 2>&1 || true

docker run -d \
  --name ntth-device \
  -p 22:2222 \
  -p 80:8080 \
  -p 445:4445 \
  ntth-honeypot:v1

echo "[+] Honeypot running (SSH/HTTP/SMB exposed)"

# ---- 4. START IDS BACKEND (AI BRAIN) ----
echo "[+] Starting IDS brain..."
cd "$BASE_DIR/backend"

source venv/bin/activate

# Ensure dataset exists
mkdir -p data
IDS_CSV="data/behavior.csv"

if [ ! -f "$IDS_CSV" ]; then
  echo "timestamp,ip,mac,packet_rate,port_count,unique_ports,scan_score,label" > "$IDS_CSV"
  echo "[+] Created IDS dataset"
fi

python main.py &
IDS_PID=$!

# ---- 5. START DASHBOARD ----
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
echo " Honeypot Ports  : 22 / 80 / 445"
echo " IDS Dataset     : backend/data/behavior.csv"
echo "========================================="
echo ""

wait $IDS_PID
