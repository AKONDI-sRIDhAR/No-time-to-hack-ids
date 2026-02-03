# NO TIME TO HACK - FINAL SYSTEM

**Status:** PRODUCTION READY
**Architecture:** Autonomous Linux Gateway (IDS + Deception)

## 🏗️ System Architecture

1.  **IDS Core (`backend/ids.py`)**
    *   Sniffs ARP/IP traffic.
    *   Tracks Trust Score (0-100) per device.
    *   Auto-saves state to `backend/data/devices.json`.
    *   Detects Scans, Floods, and Anomalies (Isolation Forest).

2.  **Deception Grid**
    *   **Protocol Emulators (`backend/decoys.py`):**
        *   MQTT (1883), CoAP (5683), UPnP (1900).
        *   Always on. Logs to `honeypot.csv`.
    *   **High-Interaction Honeypots (`backend/docker_honeypot.py`):**
        *   **Cowrie** (SSH/Telnet) on internal 2222.
        *   **Nginx** (Web) on internal 8080.
        *   **Dionaea** (SMB) on internal 4445.
    *   **Redirection Logic:**
        *   Trust Score < 40 -> Redirects specific victim traffic (22->2222, 80->8080, 445->4445).

3.  **Response Engine (`backend/response.py` & `correlation.py`)**
    *   **Correlation:** Scan + Honeypot touch = Immediate Compromise.
    *   **Isolation:** Trust Score < 20 -> DROPS all traffic.
    *   **Evidence:** Auto-zips logs on isolation.

4.  **Unified Dashboard**
    *   Hosted at `http://192.168.10.1:5000`.
    *   Real-time logic. No separate Node server.

## 🚀 How to Demo

### 1. Start the System
```bash
sudo ./run.sh
```
*   Verifies Docker containers.
*   Starts Flask Backend (IDS + API).
*   Starts Lightweight Decoys.

### 2. Connect & Observe
*   Connect a phone/laptop to the Gateway AP.
*   Dashboard: Device appears as **ONLINE** (Green/Yellow).

### 3. Attack Simulation
*   **Step A: Scan**
    Run `nmap -sS -p 22,80,445 192.168.10.1`
    *   *Result:* Trust Score drops. Status -> **SUSPICIOUS** (Orange).
*   **Step B: Probe (Trigger Redirection)**
    Try `ssh root@192.168.10.1`.
    *   *Result:* You are transparently redirected to Cowrie (Fake Banner).
    *   *Result:* Dashboard Status -> **DECEIVED** (Purple).
*   **Step C: Malicious Action**
    Brute force or interact with SMB.
    *   *Result:* Trust Score hits 0. Status -> **CONTAINED** (Red).
    *   *Evidence:* `backend/data/evidence_*.zip` created.

## 📂 Data & Logs
*   `backend/data/devices.json` -> Persistent Device Registry.
*   `backend/data/behavior.csv` -> Traffic Stats (for ML).
*   `backend/data/honeypot.csv` -> Attacker Interactions (Unified Log).

## 🧪 Forensics
On Isolation or "Doomsday", download the **Evidence Zip** from the data directory.
Contains full CSV logs + iptables history.
