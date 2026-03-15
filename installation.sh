#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

log() {
  printf '\033[1;34m[INSTALL]\033[0m %s\n' "$1"
}

fail() {
  printf '\033[1;31m[ERROR]\033[0m %s\n' "$1" >&2
  exit 1
}

if [[ ${EUID} -ne 0 ]]; then
  fail "Run as root: sudo ./installation.sh"
fi

if ! command -v iw >/dev/null 2>&1; then
  apt-get update
  apt-get install -y iw
fi

WIFI_IFACE="$(iw dev | awk '$1=="Interface"{print $2; exit}')"
[[ -n "${WIFI_IFACE}" ]] || fail "No wireless interface detected by 'iw dev'."

log "Wireless interface detected: ${WIFI_IFACE}"
log "Installing offline runtime dependencies"
apt-get update
apt-get install -y \
  hostapd \
  dnsmasq \
  docker.io \
  iptables \
  iproute2 \
  rfkill \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  build-essential \
  libffi-dev \
  libssl-dev \
  python3-numpy \
  python3-pandas \
  python3-sklearn

systemctl enable docker >/dev/null 2>&1 || true
systemctl disable hostapd dnsmasq >/dev/null 2>&1 || true

log "Installing Python packages"
python3 -m pip install --upgrade pip
python3 -m pip install -r backend/requirements.txt

mkdir -p backend/models backend/data

log "Writing hostapd configuration"
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

log "Writing dnsmasq configuration"
cat >/etc/dnsmasq.d/no_time_to_hack.conf <<'EOF'
interface=wlan0
bind-interfaces
dhcp-range=192.168.10.10,192.168.10.200,255.255.255.0,12h
dhcp-option=3,192.168.10.1
dhcp-option=6,192.168.10.1
log-queries
log-dhcp
EOF

log "Enabling IPv4 forwarding"
python3 - <<'PY'
from pathlib import Path
path = Path("/etc/sysctl.conf")
text = path.read_text() if path.exists() else ""
lines = [line for line in text.splitlines() if not line.startswith("net.ipv4.ip_forward=")]
lines.append("net.ipv4.ip_forward=1")
path.write_text("\n".join(lines) + "\n")
PY
sysctl -w net.ipv4.ip_forward=1 >/dev/null

chmod +x installation.sh no_time_to_hack.sh run.sh backend/honeypot_entrypoint.sh

log "Starting Docker and building local deception image"
systemctl start docker
docker build -t ntth-honeypot:v1 .

log "Training ensemble models"
python3 backend/train_ensemble.py

log "Installation complete"
printf '\nRun the system with:\n  sudo ./no_time_to_hack.sh\n'
