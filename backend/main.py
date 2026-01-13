from fastapi import FastAPI
import threading
from ids import start_ids, alerts

app = FastAPI()

@app.get("/alerts")
def get_alerts():
    return alerts[-10:]

threading.Thread(target=start_ids, daemon=True).start()
