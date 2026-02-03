# NO TIME TO HACK - UPGRADE SUMMARY

This system has been upgraded to a production-grade Autonomous IoT Security Gateway.

## 🚀 New Features Implemented

### 1. Protocol & App-Layer Correlation Engine (`backend/correlation.py`)
*   **What it does:** Links network anomalies (IDS) with application layer events (Honeypot logs).
*   **Logic:** If `IP X` scans ports AND interacts with a honeypot within 5 minutes, Trust Score is slashed by 40 points immediately.
*   **Evidence:** Alerts now show "Correlation: Anomaly + Honeypot Interaction".

### 2. ML Explainability Layer
*   **What it does:** Dashboard alerts now explain *why* a device is suspicious.
*   **Example Output:** `Behavioral Anomaly | High Rate, Port Scan | Score: 70`

### 3. Deception Utilities (`backend/deception_utils.py`)
*   **Honeytokens:** Infrastructure for validating fake credentials (stubbed for future expansion).
*   **Dynamic Banners:** Logic to generate fake service banners matching common IoT devices.

### 4. Attack Simulation Tool (`backend/tools/simulate_attack.sh`)
*   **Usage:** `./backend/tools/simulate_attack.sh <GATEWAY_IP>`
*   **Effect:** safely triggers the entire detection -> deception -> containment chain.

## 🧪 Verification Steps (Demo Flow)

1.  **Start System:** `sudo ./run.sh`
2.  **Access Dashboard:** `http://192.168.10.1:5000`
3.  **Run Simulation:**
    ```bash
    chmod +x backend/tools/simulate_attack.sh
    ./backend/tools/simulate_attack.sh 192.168.10.1
    ```
4.  **Observe Dashboard:**
    *   **Phase 1:** Status turns ORANGE (Suspicious - Port Scan).
    *   **Phase 2:** Status turns PURPLE (Deceived - SSH Brute Force).
    *   **Phase 3:** Alert updates to "Correlation: Anomaly + Honeypot Interaction".
    *   **Phase 4:** Trust Score drops below 20 -> RED (Contained).

## 📂 Architecture Changes
*   **`ids.py`:** Now integrates `correlation.py` after anomaly detection.
*   **`main.py`:** parses rich explanation strings for frontend display.
*   **`backend/data/`:** Remains single source of truth (`behavior.csv`, `honeypot.csv`).

## 🛡️ Autonomous Logic
*   **Trust Score:** 0-100 logic is now reinforced by honeypot verification.
*   **Deception:** Always precedes isolation (Observe -> Deceive -> Contain).
