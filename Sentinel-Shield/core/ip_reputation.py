import time

# Simple in-memory reputation store
ip_reputation_db = {}

# Thresholds (tunable, explainable)
SUSPICIOUS_THRESHOLD = 3
MALICIOUS_THRESHOLD = 6
WINDOW_SECONDS = 300  # 5 minutes


def update_ip_reputation(ip, malicious_detected):
    now = time.time()

    record = ip_reputation_db.get(ip, {
        "malicious_count": 0,
        "first_seen": now,
        "last_seen": now,
        "status": "CLEAN"
    })

    record["last_seen"] = now

    if malicious_detected:
        record["malicious_count"] += 1

    # Time window reset (prevents permanent punishment)
    if now - record["first_seen"] > WINDOW_SECONDS:
        record["malicious_count"] = 0
        record["first_seen"] = now
        record["status"] = "CLEAN"

    # Reputation logic
    if record["malicious_count"] >= MALICIOUS_THRESHOLD:
        record["status"] = "MALICIOUS"
    elif record["malicious_count"] >= SUSPICIOUS_THRESHOLD:
        record["status"] = "SUSPICIOUS"

    ip_reputation_db[ip] = record
    return record