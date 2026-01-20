import json
import re

with open("rules/attack_signatures.json") as f:
    RULES = json.load(f)

def detect_attack(normalized_request):
    matches = []

    for attack_type, rule in RULES.items():
        for pattern in rule["patterns"]:
            if re.search(pattern, normalized_request):
                matches.append({
                    "type": attack_type,
                    "severity": rule["severity"],
                    "pattern": pattern
                })

    return matches