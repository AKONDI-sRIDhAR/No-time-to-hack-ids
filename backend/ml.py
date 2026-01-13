import pandas as pd
import os

DATASET = "backend/dataset.csv"

def init_dataset():
    if not os.path.exists(DATASET):
        with open(DATASET, "w") as f:
            f.write("timestamp,ip,mac,packet_rate,port_count,unique_ports,scan_score,label\n")

def calculate_score(packet_rate, unique_ports):
    score = 0
    if packet_rate > 50:
        score += 2
    if unique_ports > 10:
        score += 3
    return score

def log_event(row):
    with open(DATASET, "a") as f:
        f.write(",".join(map(str, row)) + "\n")

def is_anomalous(packet_rate, unique_ports):
    score = calculate_score(packet_rate, unique_ports)
    return score >= 4, score
