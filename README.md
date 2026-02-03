# NO TIME TO HACK (NTTH) – Autonomous IoT Security Gateway

**Status:** PRODUCTION READY  
**Architecture:** Autonomous Linux Gateway (IDS + Deception)

NTTH is an intelligent Intrusion Detection System (IDS) and Deception System designed for Linux Gateways (Kali Linux / Raspberry Pi). It acts as a smart Wi-Fi Access Point that monitors traffic, detects anomalies using Machine Learning, and automatically redirects attackers to a Docker-based Honeypot Grid—trapping them without exposing your real infrastructure.

---

## 🚀 Key Features

*   **Autonomous Defense:** No human intervention required.
*   **Real-Time IDS:** Detects Nmap scans, packet floods, and anomalous ports using Scapy & ML.
*   **Deception Grid:** Instantly deploys high-interaction honeypots (SSH, HTTP, SMB) via Docker.
*   **Smart Redirection:** Seamlessly redirects attacker traffic to honeypots using `iptables` NAT.
*   **Protocol Emulation:** Lightweight listeners for MQTT, CoAP, and UPnP to catch IoT-specific probes.
*   **Forensics:** Auto-generates evidence ZIPs (logs + pcap) when a threat is contained.
*   **Unified Dashboard:** A single glass-pane view for monitoring, alerts, and manual overrides.

---

## 🛠️ System Architecture

1.  **IDS Core (`backend/ids.py`)**  
    Sniffs ARP/IP traffic, tracks device **Trust Scores (0-100)**, and persists state to `backend/data/devices.json`.

2.  **Response Engine (`backend/response.py` & `correlation.py`)**  
    *   **Deceive:** Trust Score < 40 → Redirects traffic (22→2222, 80→8080, 445→4445).
    *   **Isolate:** Trust Score < 20 → Blocks device completely.
    *   **Correlate:** Scan + Honeypot touch = Immediate Compromise.

3.  **Honeypot Grid (Docker)**  
    *   **SSH:** Cowrie (Port 2222) - Logs credentials and commands.
    *   **HTTP:** Nginx (Port 8080) - Fake Admin Interface.
    *   **SMB:** Dionaea (Port 4445) - Captures malware and file interactions.

---

## 📥 Installation

**Prerequisites:**  
*   Kali Linux (Physical or VM) acting as Gateway
*   Wi-Fi Adapter (AP mode supported) or Ethernet
*   Docker installed (`sudo apt install docker.io`)
*   Python 3 & Root privileges

**Setup:**
```bash
git clone https://github.com/YourRepo/No-time-to-hack-ids.git
cd No-time-to-hack-ids
chmod +x run.sh
```

---

## ⚡ How to Run

1.  **Start the System:**
    ```bash
    sudo ./run.sh
    ```
    *   *This checks Docker, builds containers, and starts the Backend + Dashboard.*

2.  **Access Dashboard:**  
    Open `http://<GATEWAY_IP>:5000` (Default: `http://192.168.10.1:5000`)

---

## 🧪 How to Demo (Attack Simulation)

Follow these steps to see the system in action:

### 1. Connect & Observe
Connect a phone or laptop to the Gateway AP.  
**Result:** Device appears as **ONLINE** (Green) on the dashboard.

### 2. Reconnaissance (Scan)
Run `nmap -sS -p 22,80,445 <GATEWAY_IP>`  
**Result:**  
*   Trust Score drops.  
*   Status becomes **SUSPICIOUS** (Orange).  
*   Alert: "Port Scan Detected".

### 3. Exploitation (Triggers Deception)
Try `ssh root@<GATEWAY_IP>` or `curl http://<GATEWAY_IP>`  
**Result:**  
*   You are transparently redirected to the Honeypot (Fake Banner).  
*   Status becomes **DECEIVED** (Purple).  
*   **Deception Grid** panel on Dashboard logs your credentials.

### 4. Containment
Continue the attack (e.g., brute force).  
**Result:**  
*   Trust Score hits 0.  
*   Status becomes **CONTAINED** (Red).  
*   Device is blocked from the network.  
*   Evidence ZIP created in `backend/data/`.

---

## 🐳 Docker Honeypot Details

The system automatically manages these containers. You don't need to run them manually, but here is the mapping for reference:

| Service | Real Port | Internal Honeypot Port | Container |
| :--- | :--- | :--- | :--- |
| **SSH** | 22 | 2222 | `ntth-honeypot` (Cowrie) |
| **HTTP** | 80 | 8080 | `http-hp` (Nginx) |
| **SMB** | 445 | 4445 | `smb-honeypot` (Dionaea) |

**Manual Docker Commands (Troubleshooting):**
```bash
# Check status
sudo docker ps

# View Raw Logs
sudo docker logs -f ntth-device
```

---

## 📁 Data & Forensics

*   **Registry:** `backend/data/devices.json` (Persistent device list)
*   **Traffic Stats:** `backend/data/behavior.csv` (ML Dataset)
*   **Attacker Logs:** `backend/data/honeypot.csv` (Unified Interaction Log)
*   **Evidence:** On isolation, a ZIP file is created in `backend/data/` containing all relevant logs for forensics.

---

## ⚠️ Disclaimer
For educational purposes only. Use responsibly on networks you own or have permission to test.
