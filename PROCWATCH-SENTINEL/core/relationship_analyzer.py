import psutil
from telemetry.event_store import add_event

def analyze_relationships():
    for proc in psutil.process_iter(['pid', 'ppid', 'name']):
        try:
            parent = psutil.Process(proc.info['ppid'])
            add_event(
                source="relationship_analyzer",
                event_type="PROCESS_RELATIONSHIP",
                severity="LOW",
                details={
                    "child": proc.info['name'],
                    "parent": parent.name()
                }
            )
        except Exception:
            continue
