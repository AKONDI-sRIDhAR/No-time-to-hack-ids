#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$1"
}

if [[ ${EUID} -ne 0 ]]; then
  echo "[-] Run as root: sudo ./no_time_to_hack.sh"
  exit 1
fi

log "NO TIME TO HACK startup initiated"

WIFI_IFACE="$(iw dev | awk '$1=="Interface"{print $2; exit}')"
if [[ -z "${WIFI_IFACE}" ]]; then
  log "No wireless interface found via iw dev"
  exit 1
fi

log "Wireless interface detected: ${WIFI_IFACE}"

if [[ "${WIFI_IFACE}" != "wlan0" ]]; then
  log "Renaming ${WIFI_IFACE} -> wlan0 (for Trinity compatibility)"
  ip link set "${WIFI_IFACE}" down || true
  ip link set "${WIFI_IFACE}" name wlan0
fi

log "Stopping client networking services"
systemctl stop NetworkManager || true
systemctl stop wpa_supplicant || true
pkill wpa_supplicant >/dev/null 2>&1 || true

log "Configuring wlan0 in AP mode"
iw reg set US
rfkill unblock all
ip link set wlan0 down
iw dev wlan0 set type __ap
ip addr flush dev wlan0
ip addr add 192.168.10.1/24 dev wlan0
ip link set wlan0 up

log "Starting dnsmasq + hostapd"
systemctl restart dnsmasq
systemctl restart hostapd

log "Starting Docker engine"
systemctl start docker

start_container() {
  local name="$1"
  local run_cmd="$2"

  if docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
    log "${name} already running"
    return
  fi

  docker start "${name}" >/dev/null 2>&1 || true
  if docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
    log "${name} started"
    return
  fi

  eval "${run_cmd}" >/dev/null 2>&1 || true
  if docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
    log "${name} created + running"
  else
    log "${name} failed to start"
  fi
}

start_container "ntth-device" "docker rm -f ntth-device; docker run -d --name ntth-device --restart always -p 2222:2222 ntth-honeypot:v1"
start_container "http-hp" "docker rm -f http-hp; docker run -d --name http-hp --restart always -p 8080:80 nginx:alpine"
start_container "smb-honeypot" "docker rm -f smb-honeypot; docker run -d --name smb-honeypot --restart always -p 4445:445 dinotools/dionaea"

log "Launching IDS backend + Flask dashboard"
exec python3 backend/main.py