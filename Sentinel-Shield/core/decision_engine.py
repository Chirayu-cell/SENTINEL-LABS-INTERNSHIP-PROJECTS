def make_decision(behavior, detections):
    score = behavior["risk_score"]
    attack_types = {d["type"] for d in detections}

    # Immediate blocks for critical classes
    if "COMMAND_INJECTION" in attack_types:
        return "BLOCK"

    if "RCE" in attack_types:
        return "BLOCK"

    # High-risk but not instant
    if "SQL_INJECTION" in attack_types and score >= 7:
        return "CHALLENGE"

    # LFI should never be fully allowed
    if "LFI" in attack_types and score >= 1:
        return "MONITOR"

    # Default score-based logic
    if score >= 20:
        return "BLOCK"
    elif score >= 10:
        return "CHALLENGE"
    elif score >= 5:
        return "MONITOR"
    else:
        return "ALLOW"