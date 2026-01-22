import threading
import time
import os
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from ids import start_ids_cycle
from response import deploy_honeypot, isolate, lockdown_network
import docker_honeypot

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")
DATA_DIR = os.path.join(BASE_DIR, "data")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

SYSTEM_STATE = {
    "status": "NORMAL",
    "devices": [],
    "alerts": [],
    "honeypot_logs": []
}

def system_loop():
    print("[MAIN] System Loop Started")

    if os.name != "nt":
        docker_honeypot.start_honeypot()

    while True:
        try:
            threats, active_devices = start_ids_cycle(timeout=5)
            SYSTEM_STATE["devices"] = active_devices

            for ip in threats:
                alert = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "ip": ip,
                    "type": "Behavioral Anomaly",
                    "action": "Redirecting to Honeypot"
                }
                SYSTEM_STATE["alerts"].insert(0, alert)
                SYSTEM_STATE["alerts"] = SYSTEM_STATE["alerts"][:50]
                deploy_honeypot(ip)

            docker_honeypot.parse_logs()
        except Exception as e:
            print(f"[MAIN] Loop Error: {e}")

        time.sleep(1)

def load_honeypot_logs():
    csv_path = os.path.join(DATA_DIR, "honeypot.csv")
    logs = []

    if os.path.exists(csv_path):
        with open(csv_path) as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split(",")
                if len(parts) >= 6:
                    logs.insert(0, {
                        "timestamp": parts[0],
                        "ip": parts[1],
                        "service": parts[2],
                        "credential": f"{parts[3]}:{parts[4]}",
                        "ua": parts[5]
                    })

    return logs[:20]

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/api/devices")
def get_devices():
    return jsonify(SYSTEM_STATE["devices"])

@app.route("/api/alerts")
def get_alerts():
    return jsonify(SYSTEM_STATE["alerts"])

@app.route("/api/honeypot")
def get_honeypot():
    return jsonify(load_honeypot_logs())

@app.route("/api/doomsday", methods=["POST"])
def doomsday():
    SYSTEM_STATE["status"] = "LOCKDOWN"
    lockdown_network()
    return jsonify({"status": "LOCKDOWN"})

if __name__ == "__main__":
    t = threading.Thread(target=system_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000)
