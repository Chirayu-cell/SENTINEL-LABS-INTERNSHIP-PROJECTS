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