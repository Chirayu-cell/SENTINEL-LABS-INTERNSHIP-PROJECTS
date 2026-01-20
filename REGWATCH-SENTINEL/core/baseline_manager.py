import json
import os
from core.registry_scanner import scan_registry

def load_or_create_baseline(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)

    baseline = scan_registry()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w") as f:
        json.dump(baseline, f, indent=4)

    return baseline
