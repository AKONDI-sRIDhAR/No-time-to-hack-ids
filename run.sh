#!/bin/bash

# Safe startup script for NO TIME TO HACK

echo "========================================"
echo "   NO TIME TO HACK // AUTONOMOUS IDS    "
echo "========================================"

# Check Root
if [ "$(id -u)" != "0" ]; then
   echo "❌ ERROR: This system requires ROOT privileges."
   echo "   Please run with sudo: sudo ./run.sh"
   exit 1
fi

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ ERROR: Python 3 could not be found."
    exit 1
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ ERROR: Docker is not installed."
    echo "   Please install: sudo apt-get install docker.io"
    exit 1
fi

# Check Docker Service
if ! systemctl is-active --quiet docker; then
    echo "[!] Starting Docker service..."
    systemctl start docker
fi

# Dependency Check (Simple)
echo "[*] checking dependencies..."
if ! pip3 freeze | grep -q "scapy"; then
    echo "[!] Installing dependencies..."
    pip3 install -r backend/requirements.txt
fi

# Set Permissions
chmod +x backend/*.py

# Export Python Path just in case
export PYTHONPATH=$PYTHONPATH:$(pwd)/backend

# Start Main Orchestrator
echo "[+] Starting System Core..."
cd backend
python3 main.py
