import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_LOG = os.path.join(BASE_DIR, "logs", "alerts.log")

def log_alert(alert):
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")