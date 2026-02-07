import threading
import time
import os
import csv
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from ids import start_ids_cycle, known_devices, save_devices, lock
from response import deploy_honeypot, isolate, lockdown_network, release_attacker
import docker_honeypot
import sys

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
        try:
            import decoys
            decoys.start_decoys()
        except ImportError:
            pass

    while True:
        try:
            threats, active_devices = start_ids_cycle(timeout=5)
            SYSTEM_STATE["devices"] = active_devices

            # Handle Threats with Protection Ladder
            if threats:
                for threat in threats:
                    ip = threat.get("ip")
                    if not ip: continue

                    score = threat.get("score", 0)
                    trust = threat.get("trust", 50)
                    flags = threat.get("flags", {})
                    
                    action_msg = "Monitoring"
                    
                    if flags.get("redirected", False):
                        deploy_honeypot(ip)
                        action_msg = "Redirecting to Honeypot"
                        
                    if flags.get("isolated", False):
                        isolate(ip)
                        action_msg = "ISOLATED & Redirected"

                    explanation = threat.get("reason", "Unknown Anomaly")
                    if "correlation" in threat:
                        explanation += f" | {threat['correlation']}"

                    # Alert if significant action or anomaly
                    if flags.get("redirected") or flags.get("isolated") or score > 50:
                        alert = {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "ip": ip,
                            "type": f"Trust: {trust} | {explanation}", 
                            "action": action_msg
                        }
                        
                        # Avoid duplicate alerts at top
                        if not SYSTEM_STATE["alerts"] or SYSTEM_STATE["alerts"][0]["type"] != alert["type"] or SYSTEM_STATE["alerts"][0]["ip"] != ip:
                            SYSTEM_STATE["alerts"].insert(0, alert)
                            SYSTEM_STATE["alerts"] = SYSTEM_STATE["alerts"][:50]
                            print(f"[MAIN] Protection Active: {action_msg} for {ip} (Reason: {explanation})")

            # Parse logs less frequently? Or every cycle?
            # Every cycle (approx 5s) is fine.
            docker_honeypot.parse_logs()
        except Exception as e:
            print(f"[MAIN] Loop Error: {e}")

        time.sleep(1)

def load_honeypot_logs():
    csv_path = os.path.join(DATA_DIR, "honeypot.csv")
    logs = []

    if os.path.exists(csv_path):
        try:
            with open(csv_path, newline="") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if header:
                    for row in reader:
                        if len(row) >= 6:
                            # timestamp, source_ip, service, username, password, metadata
                            logs.insert(0, {
                                "timestamp": row[0],
                                "ip": row[1],
                                "service": row[2],
                                "credential": f"{row[3]}:{row[4]}",
                                "ua": row[5]
                            })
        except Exception:
            pass

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

@app.route("/api/action/<action>/<ip>", methods=["POST"])
def manual_action(action, ip):
    print(f"[API] Manual Action: {action} on {ip}")
    
    with lock:
        target_mac = None
        info = None
        
        for mac, data in known_devices.items():
            if data.get("ip") == ip:
                target_mac = mac
                info = data
                break
                
        if not info:
            return jsonify({"error": "Device not found"}), 404
        
        if action == "isolate":
            isolate(ip)
            info["flags"]["isolated"] = True
            info["trust_score"] = 0
        elif action == "release":
            release_attacker(ip)
            info["flags"]["isolated"] = False
            info["flags"]["redirected"] = False
            info["flags"]["quarantined"] = False
            info["trust_score"] = 50
        elif action == "quarantine":
            info["flags"]["quarantined"] = True
            info["trust_score"] = 50
        elif action == "redirect":
            deploy_honeypot(ip)
            info["flags"]["redirected"] = True
            info["trust_score"] = 20
            
        save_devices()
        
    return jsonify({"status": "OK", "action": action, "ip": ip})

if __name__ == "__main__":
    t = threading.Thread(target=system_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000)
