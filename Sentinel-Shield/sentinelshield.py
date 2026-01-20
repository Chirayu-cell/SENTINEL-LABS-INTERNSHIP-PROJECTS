from datetime import datetime
from core.normalizer import normalize_request
from core.detector import detect_attack
from core.behavior_tracker import update_behavior
from core.decision_engine import make_decision
from core.logger import log_event
from logs.alerts import log_alert
from core.ip_reputation import update_ip_reputation

def handle_request(ip, request):
    # 1. Normalize
    normalized = normalize_request(request)

    # 2. Detect signatures
    detections = detect_attack(normalized)

    malicious_detected = len(detections) > 0
    ip_reputation = update_ip_reputation(ip, malicious_detected)

    # 3. Update behavior
    behavior = update_behavior(ip, detections)

    # 4. Decide action
    decision = make_decision(behavior, detections)

    alert = None

    if decision in ["CHALLENGE", "BLOCK"] or ip_reputation["status"] == "MALICIOUS":
       alert = {
           "timestamp": datetime.utcnow().isoformat(),
           "ip": ip,
           "endpoint": request.split("?")[0],
           "payload": request,
           "attack_types": list(set(d["type"] for d in detections)),
           "risk_score": behavior["risk_score"],
           "decision": decision,
           "ip_reputation": ip_reputation["status"]
    }
    log_alert(alert)

    # 5. Log event
    log_event(ip, request, detections, behavior, decision, ip_reputation)

    # 6. Return structured result (IMPORTANT)
    return {
        "ip": ip,
        "request": request,
        "detections": list(set(d["type"] for d in detections)),
        "risk_score": behavior["risk_score"],
        "decision": decision,
        "ip_reputation": ip_reputation["status"]
    }

# ---------- OPTIONAL MANUAL MODE ----------
if __name__ == "__main__":
    while True:
        ip = input("IP: ")
        req = input("Request: ")
        result = handle_request(ip, req)
        print(result)