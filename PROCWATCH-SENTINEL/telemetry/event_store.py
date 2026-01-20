from datetime import datetime

_EVENTS = []

def add_event(
    source,
    event_type,
    details,
    risk_score=0,
    mitre=None,
    risk_factors=None
):
    severity = _severity_from_score(risk_score)

    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "risk_score": risk_score,
        "details": details,
        "risk_factors": risk_factors or [],
        "mitre": mitre or []
    }

    _EVENTS.append(event)

def _severity_from_score(score):
    if score >= 81:
        return "CRITICAL"
    if score >= 51:
        return "HIGH"
    if score >= 21:
        return "MEDIUM"
    return "LOW"

def get_events():
    return list(_EVENTS)

def clear_events():
    _EVENTS.clear()
