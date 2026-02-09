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

echo "[+] Checking Python dependencies (offline safe)..."

if ! python3 -c "import flask, flask_cors, pandas, sklearn, scapy, requests" 2>/dev/null; then
    echo "[-] Missing required Python dependencies."
    echo "[-] Install dependencies BEFORE entering AP mode:"
    echo "    pip install -r requirements.txt"
    exit 1
fi

echo "[✓] Dependencies OK"

# Dataset handled by backend/ml.py
mkdir -p data

# Remove deprecated var and run safely
python3 main.py
