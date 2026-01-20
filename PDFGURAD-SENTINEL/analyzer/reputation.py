import json
from pathlib import Path

BASE = Path("intel")

def _load(name):
    try:
        with open(BASE / name, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def apply_reputation(event):
    allow = _load("allowlist.json")
    block = _load("blocklist.json")

    verdicts = []

    sha256 = event["hashes"]["sha256"]
    iocs = event.get("iocs", {})

    if sha256 in allow.get("file_hashes", []):
        verdicts.append("known_good_file")

    if sha256 in block.get("file_hashes", []):
        verdicts.append("known_malicious_file")

    for d in iocs.get("domains", []):
        if d in allow.get("domains", []):
            verdicts.append(f"trusted_domain:{d}")
        if d in block.get("domains", []):
            verdicts.append(f"malicious_domain:{d}")

    for ip in iocs.get("ips", []):
        if ip in block.get("ips", []):
            verdicts.append(f"malicious_ip:{ip}")

    return verdicts
