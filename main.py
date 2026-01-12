import threading
import time
from watcher.watcher import NetworkWatcher
from brain.brain import SecurityBrain
from honeypot.honeypot import start_honeypot
from ui.app import start_ui

watcher = NetworkWatcher()
brain = SecurityBrain()
latest_state = {}

def watcher_thread():
    watcher.start()

def decision_loop():
    global latest_state
    while True:
        snapshot = watcher.get_snapshot()
        decisions = brain.analyze(snapshot)
        latest_state = {
            "devices": snapshot,
            "decisions": decisions
        }
        time.sleep(5)

def get_state():
    return latest_state

if __name__ == "__main__":
    threading.Thread(target=watcher_thread, daemon=True).start()
    threading.Thread(target=decision_loop, daemon=True).start()
    threading.Thread(target=start_honeypot, daemon=True).start()
    start_ui(get_state)
