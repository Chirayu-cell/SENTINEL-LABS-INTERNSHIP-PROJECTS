from datetime import datetime
import json

def log_event(ip, request, detections, behavior, decision, ip_reputation):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "risk_score": behavior["risk_score"],
        "decision": decision,
        "detections": [d["type"] for d in detections],
        "request": request,
        "log_ip_reputation": ip_reputation["status"]
    }

    with open("logs/sentinelshield.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")