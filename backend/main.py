import threading
import time
import os
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from ids import start_ids_cycle
from response import deploy_honeypot, isolate, lockdown_network
import docker_honeypot

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")
DATA_DIR = os.path.join(BASE_DIR, "data")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

# Global State
SYSTEM_STATE = {
    "status": "NORMAL",
    "devices": [],
    "alerts": [],
    "honeypot_logs": []
}

def system_loop():
    """Background thread for IDS and Honeypot management."""
    print("[MAIN] System Loop Started")

    # 1. Ensure Honeypot Active (LINUX ONLY)
    if os.name != "nt":
        try:
            docker_honeypot.ensure_image_built()
            docker_honeypot.start_honeypot()
        except Exception as e:
            print(f"[MAIN] Honeypot startup error: {e}")

    while True:
        try:
            # 2. IDS Cycle
            threats, active_devices = start_ids_cycle(timeout=5)

            SYSTEM_STATE["devices"] = active_devices

            if threats:
                for ip in threats:
                    alert = {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "ip": ip,
                        "type": "Behavioral Anomaly",
                        "action": "Redirecting to Honeypot"
                    }
                    SYSTEM_STATE["alerts"].insert(0, alert)
                    SYSTEM_STATE["alerts"] = SYSTEM_STATE["alerts"][:50]

                    print(f"[MAIN] Threat Detected: {ip}")

                    deploy_honeypot(ip)

            # 3. Harvest Honeypot Logs
            if os.name != "nt":
                try:
                    docker_honeypot.parse_logs()
                except Exception:
                    pass

        except Exception as e:
            print(f"[MAIN] Loop Error: {e}")

        time.sleep(1)

def load_honeypot_logs():
    csv_path = os.path.join(DATA_DIR, "honeypot.csv")
    logs = []

    if os.path.exists(csv_path):
        try:
            with open(csv_path, "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.strip().split(",")
                    if len(parts) >= 7:
                        logs.insert(0, {
                            "timestamp": parts[0],
                            "ip": parts[1],
                            "service": parts[2],
                            "credential": f"{parts[3]}:{parts[4]}",
                            "ua": parts[5]
                        })
        except Exception:
            pass

    return logs[:20]

# ---- ROUTES ----

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(FRONTEND_DIR, path)

@app.route("/api/status")
def get_status():
    return jsonify({"status": SYSTEM_STATE["status"]})

@app.route("/api/devices")
def get_devices():
    return jsonify(SYSTEM_STATE["devices"])

@app.route("/api/alerts")
def get_alerts():
    return jsonify(SYSTEM_STATE["alerts"]})

@app.route("/api/honeypot")
def get_honeypot_logs():
    return jsonify(load_honeypot_logs())

@app.route("/api/doomsday", methods=["POST"])
def activate_doomsday():
    SYSTEM_STATE["status"] = "LOCKDOWN"
    lockdown_network()
    SYSTEM_STATE["alerts"].insert(0, {
        "timestamp": time.strftime("%H:%M:%S"),
        "ip": "SYSTEM",
        "type": "DOOMSDAY",
        "action": "Network Lockdown Initiated"
    })
    return jsonify({"status": "LOCKDOWN"})

if __name__ == "__main__":
    print("[+] NO TIME TO HACK – Autonomous System Starting...")

    t = threading.Thread(target=system_loop, daemon=True)
    t.start()

    app.run(host="0.0.0.0", port=5000)
