import psutil
from telemetry.event_store import add_event

_seen_services = set()

def scan_services():
    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
            name = info['name']
            if name in _seen_services:
                continue
            _seen_services.add(name)

            add_event(
                source="service_audit",
                event_type="SERVICE_DETECTED",
                severity="LOW",
                details={
                    "name": name,
                    "status": info['status'],
                    "start_type": info['start_type'],
                    "binpath": info.get("binpath", "")
                }
            )
        except Exception:
            continue
