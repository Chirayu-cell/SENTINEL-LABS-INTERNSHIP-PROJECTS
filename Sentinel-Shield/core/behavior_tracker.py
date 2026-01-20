def generate_alert(log_entry):
    if log_entry["decision"] in ["CHALLENGE", "BLOCK"]:
        alert = {
            "time": log_entry["timestamp"],
            "ip": log_entry["ip"],
            "severity": log_entry["decision"],
            "risk_score": log_entry["risk_score"],
            "detections": log_entry["detections"]
        }
        return alert
    return None
                                                                                                                                                                           
#┌──(root㉿cracker007)-[/var/www/sentinelshield/core]
#└─# cat behavior_tracker.py 
import time
from collections import defaultdict

behavior_db = defaultdict(lambda: {
    "requests": [],
    "malicious_hits": 0,
    "risk_score": 0
})

SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 5,
    "CRITICAL": 8
}

TIME_WINDOW = 60   # seconds
MAX_REQUESTS = 30  # per window
BLOCK_SCORE = 15

def update_behavior(ip, detections):
    now = time.time()
    record = behavior_db[ip]

    # Clean old requests
    record["requests"] = [t for t in record["requests"] if now - t < TIME_WINDOW]
    record["requests"].append(now)

    # Rate-based risk
    if len(record["requests"]) > MAX_REQUESTS:
        record["risk_score"] += 5

    # Signature-based risk
    for d in detections:
        weight = SEVERITY_WEIGHT.get(d["severity"], 1)
        record["risk_score"] += weight if record["malicious_hits"] == 0 else weight // 2
        record["malicious_hits"] += 1

    return record

def reset_behavior():
    behavior_db.clear()