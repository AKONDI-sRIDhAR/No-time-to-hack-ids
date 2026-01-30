# NO TIME TO HACK (NTTH) – Autonomous IoT Security Gateway

An autonomous Intrusion Detection System (IDS) and Deception System designed for Linux Gateways (Kali Linux / Raspberry Pi). This system acts as a Wi-Fi Access Point, monitors all traffic for anomalies behaviorally, and automatically redirects attackers to a Docker-based Honeypot Grid without exposing the real system.

## 🚀 Features

*   **Autonomous Operation:** No human intervention need.
*   **Real-Time IDS:** Detects Nmap scans, packet floods, anomalous ports.
*   **Behavioral ML:** Learns device behavior over time (Unsupervised Anomaly Detection).
*   **Docker Deception Grid:** Instantly spins up a honeypot (Cowrie++) pretending to be a vulnerable IoT device.
*   **Smart Response:** Redirects attacker traffic (SSH, HTTP, SMB) to the honeypot seamlessly using `iptables` NAT.
*   **Cyber Dashboard:** Real-time visibility of threats and captured credentials.

## 🛠️ Installation

**Requirements:**
*   Kali Linux (Physical or VM) acting as Gateway
*   Wi-Fi Adapter (supporting AP mode) or Wired upstream
*   Docker installed (`apt install docker.io`)
*   Python 3 & Root privileges

**Clone & Setup:**
```bash
git clone https://github.com/YourRepo/No-time-to-hack-ids.git
cd No-time-to-hack-ids
chmod +x run.sh
```

## 🧪 Demonstration Flow (How to Demo)

Follow the below steps exactly to demonstrate the system's capabilities.

### 1. Boot & Network Setup
*   Ensure Kali Linux is running.
*   Run the AP Mode script:
    ```bash
    sudo ./apmode.sh
    ```

### 2. Start the Autonomous System
*   Run the main system script:
    ```bash
    sudo ./run.sh
    ```
*   The system will:
    *   Verify Docker availability.
    *   Build/Start the `ntth-honeypot` container.
    *   Start the IDS Engine and Web Server.
*   **UI Dashboard:** Open `http://localhost:5000` (or Gateway IP) in your browser.

### 3. Attack Simulation
*   From an **Attacker Device** (connected to the same network):
    *   Run an Nmap scan against the Gateway:
        ```bash
        nmap -sS -p 22,80,445 <GATEWAY_IP>
        ```
    *   Try to SSH into the Gateway:
        ```bash
        ssh root@<GATEWAY_IP>
        ```
    *   Try to access HTTP:
        ```bash
        curl http://<GATEWAY_IP>
        ```

### 4. Observe Reaction
1.  **Detection:** The Dashboard will flash a **THREAT DETECTED** alert.
2.  **Redirection:** The system automatically executes `iptables` rules to redirect the attacker's traffic to the Docker Container.
3.  **Capture:**
    *   The Nmap scan will show ports as OPEN (serviced by Honeypot).
    *   The SSH login will land in the Cowrie honeypot (logging credentials).
4.  **Evidence:**
    *   Check the "Deception Grid" section in the Dashboard.
    *   You will see the Attacker IP, Credentials tried, and Commands run.

### 5. Doomsday Protocol (Optional)
*   If the threat escalates, click **ACTIVATE DOOMSDAY PROTOCOL** on the Dashboard.
*   **Effect:** The Network is completely locked down. All forwarding is dropped. The attacker is isolated.

## 📂 Architecture

*   **Brain (`backend/ml.py`):** Isolation Forest model for anomaly detection.
*   **Eyes (`backend/ids.py`):** Scapy-based sniffer for traffic analysis.
*   **Muscle (`backend/response.py`):** Iptables manager and Docker integrator.
*   **Deception (`backend/docker_honeypot.py`):** Container manager for high-interaction honeypots.

## ⚠️ Disclaimer
Educational purpose only. Use responsibly on networks you own.
