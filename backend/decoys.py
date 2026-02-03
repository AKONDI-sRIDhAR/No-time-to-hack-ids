import socket
import threading
import time
import os
import csv

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
HONEYPOT_CSV = os.path.join(DATA_DIR, "honeypot.csv")

# Emulated Services
PORTS = {
    "MQTT": 1883,
    "CoAP": 5683, # UDP
    "UPnP": 1900  # UDP
}

def log_interaction(ip, service, data_snippet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    # CSV Format: timestamp,source_ip,username,password,user_agent/metadata
    # We map: service -> service, data -> password? No. 
    # Let's map: 
    # timestamp, ip, service, "n/a", data, "Protocol Emulator"
    row = [timestamp, ip, service, "n/a", data_snippet.replace(",", " "), "Protocol Emulator"]
    
    try:
        with open(HONEYPOT_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(row)
    except Exception as e:
        print(f"[DECOYS] Log Error: {e}")

def handle_tcp(client, addr, service):
    ip = addr[0]
    try:
        data = client.recv(1024)
        if data:
            log_interaction(ip, service, f"Payload: {data.hex()[:20]}")
            # Basic MQTT CONNACK if MQTT
            if service == "MQTT":
                # CONNACK: 0x20 0x02 0x00 0x00
                client.send(b'\x20\x02\x00\x00')
    except Exception:
        pass
    finally:
        client.close()

def handle_udp(sock, service):
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            ip = addr[0]
            log_interaction(ip, service, f"Payload: {data.hex()[:20]}")
            
            # Basic Responses
            if service == "CoAP":
                # Empty ACK (Reset header usually, but simple ACK here)
                # Header: Ver=1, T=2(ACK), TKL=0, Code=0.00, MIM=MessageID
                if len(data) >= 4:
                    msg_id = data[2:4]
                    resp = b'\x60\x00' + msg_id
                    sock.sendto(resp, addr)
                    
            if service == "UPnP":
                # SSDP Response
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "CACHE-CONTROL: max-age=1800\r\n"
                    "ST: upnp:rootdevice\r\n"
                    "USN: uuid:fake-device::upnp:rootdevice\r\n\r\n"
                ).encode()
                sock.sendto(resp, addr)

        except Exception as e:
            print(f"[DECOYS] UDP Error: {e}")

def run_tcp_server(port, service):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        print(f"[DECOYS] {service} listening on {port}/TCP")
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_tcp, args=(client, addr, service)).start()
    except Exception as e:
        print(f"[DECOYS] Failed to bind {service}: {e}")

def run_udp_server(port, service):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        print(f"[DECOYS] {service} listening on {port}/UDP")
        threading.Thread(target=handle_udp, args=(sock, service)).start()
    except Exception as e:
        print(f"[DECOYS] Failed to bind {service}: {e}")

def start_decoys():
    threading.Thread(target=run_tcp_server, args=(PORTS["MQTT"], "MQTT"), daemon=True).start()
    threading.Thread(target=run_udp_server, args=(PORTS["CoAP"], "CoAP"), daemon=True).start()
    threading.Thread(target=run_udp_server, args=(PORTS["UPnP"], "UPnP"), daemon=True).start()

if __name__ == "__main__":
    start_decoys()
    while True:
        time.sleep(1)
