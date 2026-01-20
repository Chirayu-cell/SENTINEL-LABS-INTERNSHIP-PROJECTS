#!/usr/bin/env python3
"""
SentinelShield Detection Replay Engine

Replays known attack patterns against the detection engine
and validates expected detections and decisions.

Purpose:
- Regression testing
- Detection tuning
- Demo / presentation evidence
"""

import os
import sys
import json

# Ensure project root is in PYTHONPATH
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from sentinelshield import handle_request
from core.behavior_tracker import reset_behavior


def load_tests(path: str) -> list:
    """Load attack test cases from JSON."""
    with open(path, "r") as f:
        return json.load(f)


def run_tests():
    tests_path = os.path.join("tests", "attack_tests.json")
    tests = load_tests(tests_path)

    print("\n=== SentinelShield Detection Replay ===\n")

    for test in tests:
        reset_behavior()

        result = handle_request(
            test["ip"],
            test["request"]
        )

        detected_ok = test["expected_detection"] in result["detections"]
        decision_ok = test["expected_decision"] == result["decision"]

        status = "PASS" if detected_ok and decision_ok else "FAIL"

        print(f"[{status}] {test['name']}")
        print(f"  Request:  {test['request']}")
        print(f"  Expected: {test['expected_detection']} / {test['expected_decision']}")
        print(f"  Result:   {result}\n")
        print(f"  IP Reputation: {result['ip_reputation']}")

if __name__ == "__main__":
    run_tests()