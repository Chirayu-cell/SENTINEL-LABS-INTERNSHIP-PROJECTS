import json
import os
from telemetry.event_store import get_events

LOG_FILE = "logs/wrcms_events.log"

def write_logs():
    os.makedirs("logs", exist_ok=True)

    with open(LOG_FILE, "a") as f:
        for event in get_events():
            f.write(json.dumps(event) + "\n")
