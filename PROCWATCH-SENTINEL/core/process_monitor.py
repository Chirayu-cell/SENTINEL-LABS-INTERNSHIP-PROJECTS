"""import psutil
from core.signature_utils import is_binary_signed
from detection.rules import evaluate_process

def scan_processes():
    events = []

    for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            exe_path = proc.info["exe"]
            if not exe_path:
                continue

            # 🔧 FIX: define signed BEFORE using it
            signed = is_binary_signed(exe_path)

            process_data = {
                "pid": proc.info["pid"],
                "name": proc.info["name"],
                "path": exe_path,
                "signed": signed
            }

            event = evaluate_process(process_data)
            if event:
                events.append(event)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return events

"""
import psutil
from telemetry.event_store import add_event
from core.signature_utils import is_binary_signed

_seen = set()

def scan_processes():
    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe']):
        try:
            key = (proc.info['pid'], proc.info['exe'])
            if key in _seen:
                continue
            _seen.add(key)

            signed = is_binary_signed(proc.info['exe'])
            
            add_event(
                source="process_monitor",
                event_type="PROCESS_DETECTED",
                details={
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "ppid": proc.info['ppid'],
                    "exe": proc.info['exe'],
                    "signed": signed
                },
                risk_score=5
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
