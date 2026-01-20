import json
import time
from telemetry.event_store import add_event

def detect_registry_changes(baseline_path, current_snapshot):
    with open(baseline_path, "r") as f:
        baseline = json.load(f)

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    for reg_path, base_values in baseline.items():
        current_values = current_snapshot.get(reg_path, {})

        for value, cur in current_values.items():
            if value not in base_values:
                add_event({
                    "timestamp": timestamp,
                    "registry_path": reg_path,
                    "value_name": value,
                    "change_type": "ADDED",
                    "old_value": None,
                    "new_value": cur
                })

            elif cur != base_values[value]:
                add_event({
                    "timestamp": timestamp,
                    "registry_path": reg_path,
                    "value_name": value,
                    "change_type": "MODIFIED",
                    "old_value": base_values[value],
                    "new_value": cur
                })

        for value in base_values:
            if value not in current_values:
                add_event({
                    "timestamp": timestamp,
                    "registry_path": reg_path,
                    "value_name": value,
                    "change_type": "DELETED",
                    "old_value": base_values[value],
                    "new_value": None
                })
