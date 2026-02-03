#!/bin/bash
# backend/tools/simulate_attack.sh

if [ -z "$1" ]; then
    echo "Usage: $0 <TARGET_IP>"
    echo "Simulates: Nmap Scan -> SSH Brute -> SMB Probe"
    exit 1
fi

TARGET=$1
echo "[*] Simulating Attack Sequence against $TARGET..."

echo "[1] Running Port Scan..."
nmap -p 22,80,445 -sS $TARGET --scan-delay 100ms > /dev/null

echo "[2] Simulating SSH Brute Force..."
# Just trigger 5 attempts
for i in {1..5}; do
    sshpass -p "fake" ssh -o StrictHostKeyChecking=no -p 2222 root@$TARGET "exit" 2>/dev/null &
done
wait

echo "[3] SMB Probe..."
echo "Hello" | nc $TARGET 445 > /dev/null

echo "[*] Attack Simulation Complete. Check Dashboard."
