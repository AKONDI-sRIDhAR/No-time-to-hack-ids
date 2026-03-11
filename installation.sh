#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "=============================================="
echo " NO TIME TO HACK :: ONE-TIME INSTALLATION "
echo "=============================================="

if [[ ${EUID} -ne 0 ]]; then
  echo "[-] Run as root: sudo ./installation.sh"
  exit 1
fi

if ! command -v iw >/dev/null 2>&1; then
  apt-get update
  apt-get install -y iw
fi

WIFI_IFACE="$(iw dev | awk '$1=="Interface"{print $2; exit}')"
if [[ -z "${WIFI_IFACE}" ]]; then
  echo "[-] No wireless interface detected by 'iw dev'."
  exit 1
fi

echo "[+] Detected wireless interface: ${WIFI_IFACE}"

echo "[+] Installing system dependencies..."
apt-get update
apt-get install -y \
  hostapd dnsmasq docker.io iptables iproute2 rfkill \
  python3 python3-pip python3-venv python3-dev \
  build-essential libffi-dev libssl-dev

systemctl enable docker

if ! python3 -c "import xgboost" >/dev/null 2>&1; then
  apt-get install -y python3-xgboost || true
fi
if ! python3 -c "import tensorflow" >/dev/null 2>&1; then
  apt-get install -y python3-tensorflow || true
fi

echo "[+] Installing Python dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install -r backend/requirements.txt
python3 -m pip install joblib numpy xgboost tensorflow

mkdir -p backend/models backend/data

echo "[+] Writing AP configuration..."
cat >/etc/hostapd/hostapd.conf <<'EOF'
interface=wlan0
driver=nl80211
ssid=NOTIME_TO_HACK
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=notime123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ignore_broadcast_ssid=0
EOF

cat >/etc/default/hostapd <<'EOF'
DAEMON_CONF="/etc/hostapd/hostapd.conf"
EOF

cat >/etc/dnsmasq.d/no_time_to_hack.conf <<'EOF'
interface=wlan0
bind-interfaces
dhcp-range=192.168.10.10,192.168.10.200,255.255.255.0,12h
dhcp-option=3,192.168.10.1
dhcp-option=6,192.168.10.1
log-queries
log-dhcp
EOF

sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null

systemctl disable hostapd dnsmasq >/dev/null 2>&1 || true

chmod +x installation.sh no_time_to_hack.sh

echo "[+] Building local honeypot image (ntth-honeypot:v1)..."
docker build -t ntth-honeypot:v1 .

echo "[+] Pre-pulling external honeypot images..."
docker pull nginx:alpine
docker pull dinotools/dionaea

echo "[+] Training ensemble models..."
python3 backend/train_ensemble.py

echo "=============================================="
echo "[?] Installation complete"
echo "[?] Next run: sudo ./no_time_to_hack.sh"
echo "=============================================="