#!/bin/bash
set -e

echo "[+] Switching to IDS / AP mode (temporary)"

# Make sure AP services are NOT persistent
systemctl disable hostapd dnsmasq >/dev/null 2>&1 || true

# Stop client networking (temporary)
systemctl stop NetworkManager || true
systemctl stop wpa_supplicant || true
systemctl disable NetworkManager
systemctl disable wpa_supplicant
pkill wpa_supplicant || true

# Regulatory domain (critical)
iw reg set US

# Configure wlan0 as AP
ip link set wlan0 down
iw dev wlan0 set type __ap
ip addr flush dev wlan0
rfkill unblock all
ip addr add 192.168.10.1/24 dev wlan0
ip link set wlan0 up

# Start AP stack (runtime only)
systemctl start dnsmasq
systemctl start hostapd

echo "-----------------------------------"
echo "[✓] IDS / AP MODE ACTIVE"
echo "[✓] SSID      : NOTIME_TO_HACK"
echo "[✓] Password  : notime123"
echo "[✓] Gateway   : 192.168.10.1"
echo "[✓] Reboot to return to Internet"
echo "-----------------------------------"
