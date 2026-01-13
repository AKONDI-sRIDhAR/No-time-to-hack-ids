import time
from ids import start_ids
from response import deploy_honeypot, isolate
from ml import init_dataset

init_dataset()

print("[+] NO TIME TO HACK – Autonomous IDS Started")

while True:
    attacker = start_ids()

    if attacker:
        print(f"[!] Threat detected from {attacker}")
        deploy_honeypot(attacker)
        isolate(attacker)
        print("[+] Honeypot deployed + attacker isolated")

    time.sleep(5)
