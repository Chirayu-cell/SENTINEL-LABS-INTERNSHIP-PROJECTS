from datetime import datetime, timedelta, timezone


def is_stale(last_seen: str, days: int = 30) -> bool:
    last = datetime.fromisoformat(last_seen)
    return datetime.now(timezone.utc) - last > timedelta(days=days)

def assign_severity(correlated_data: dict) -> dict:
    scored = {}

    for key, data in correlated_data.items():
        count = data["count"]

        if count >= 4:
            severity = "HIGH"
        elif count >= 2:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if severity != "LOW" and is_stale(data["last_seen"]):
            severity = "LOW"
    
        scored[key] = {
            "type": data["type"],
            "sources": data["sources"],
            "count": count,
            "severity": severity
        }

    return scored
