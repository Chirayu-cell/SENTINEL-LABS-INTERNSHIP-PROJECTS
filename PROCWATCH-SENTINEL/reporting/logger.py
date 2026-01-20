import json
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "winprocguard.log")

def write_logs(events):
    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
