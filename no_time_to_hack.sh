#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

log() {
  printf '\033[1;32m[NTTH]\033[0m %s\n' "$1"
}

fail() {
  printf '\033[1;31m[ERROR]\033[0m %s\n' "$1" >&2
  exit 1
}

if [[ ${EUID} -ne 0 ]]; then
  fail "Run as root: sudo ./no_time_to_hack.sh"
fi

WIFI_IFACE="$(iw dev | awk '$1=="Interface"{print $2; exit}')"
[[ -n "${WIFI_IFACE}" ]] || fail "No wireless interface found via 'iw dev'."

log "Using wireless interface: ${WIFI_IFACE}"

if [[ "${WIFI_IFACE}" != "wlan0" ]]; then
  log "Renaming ${WIFI_IFACE} -> wlan0 for Trinity compatibility"
  ip link set "${WIFI_IFACE}" down || true
  ip link set "${WIFI_IFACE}" name wlan0
fi

log "Preparing access point mode"
systemctl stop NetworkManager >/dev/null 2>&1 || true
systemctl stop wpa_supplicant >/dev/null 2>&1 || true
pkill wpa_supplicant >/dev/null 2>&1 || true
rfkill unblock all
iw reg set US || true
ip link set wlan0 down
iw dev wlan0 set type __ap
ip addr flush dev wlan0
ip addr add 192.168.10.1/24 dev wlan0
ip link set wlan0 up
sysctl -w net.ipv4.ip_forward=1 >/dev/null

log "Starting infrastructure services"
systemctl start docker
systemctl stop smbd nmbd samba nginx apache2 >/dev/null 2>&1 || true
systemctl restart dnsmasq
systemctl restart hostapd

if ! docker image inspect ntth-honeypot:v1 >/dev/null 2>&1; then
  log "Local honeypot image missing; rebuilding"
  docker build -t ntth-honeypot:v1 .
fi

docker rm -f ntth-grid >/dev/null 2>&1 || true
docker run -d \
  --name ntth-grid \
  --restart always \
  -p 2222:2222 \
  -p 8080:8080 \
  -p 445:445 \
  ntth-honeypot:v1 >/dev/null

log "Deception grid exposed on 2222/8080/445"
log "Launching IDS backend and dashboard"
exec python3 backend/main.py
