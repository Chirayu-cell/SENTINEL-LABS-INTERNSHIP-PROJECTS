WEIGHTS = {
    "document_action_present": 20,
    "javascript_content_detected": 20,
    "suspicious_javascript_api_usage": 30,
    "high_entropy_stream": 15,
    "embedded_payload_detected": 30,
}

def score_risk(flags):
    score = 0
    reasons = []

    for f in flags:
        if f in WEIGHTS:
            score += WEIGHTS[f]
            reasons.append(f)

    score = min(score, 100)

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "contributing_factors": reasons
    }


def adjust_score_with_reputation(risk, verdicts):
    score = risk["risk_score"]
    reasons = list(risk["contributing_factors"])

    for v in verdicts:
        if v.startswith("known_good"):
            score -= 30
            reasons.append("allowlist_match")

        elif v.startswith("known_malicious"):
            score += 40
            reasons.append("blocklist_match")

        elif v.startswith("malicious_"):
            score += 20
            reasons.append(v)

    score = max(0, min(score, 100))

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "contributing_factors": list(set(reasons))
    }
