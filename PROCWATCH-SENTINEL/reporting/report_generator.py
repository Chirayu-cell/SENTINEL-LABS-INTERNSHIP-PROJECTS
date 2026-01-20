from telemetry.event_store import get_events
from collections import Counter

MITRE_TACTICS = {
    "Execution": {"T1059", "T1047"},
    "Persistence": {"T1547.001", "T1547.009", "T1053.005"},
    "Defense Evasion": {"T1036", "T1070.004"}
}

def generate_report():
    events = get_events()

    print("\n=== FINAL DETECTION REPORT ===")
    print(f"Total Events Logged: {len(events)}")

    print("\nTop Risk Events (Explained):")

    risky = sorted(events, key=lambda e: e["risk_score"], reverse=True)[:5]

    for e in risky:
        d = e["details"]

        print("\n---------------------------------")
        print(f"Severity   : {e['severity']}")
        print(f"Risk Score : {e['risk_score']}")
        print(f"Event Type : {e['event_type']}")
        print(f"Process    : {d.get('name')} (PID {d.get('pid')})")
        print(f"Parent PID : {d.get('ppid')}")
        print(f"Executable : {d.get('exe')}")

        if e["risk_factors"]:
            print("Risk Factors:")
            for f in e["risk_factors"]:
                print(f"  - {f}")

        if e["mitre"]:
            print("MITRE ATT&CK:")
            for t in e["mitre"]:
                print(f"  - {t}")


    print("\nSeverity Distribution:")
    for k, v in Counter(e["severity"] for e in events).items():
        print(f"  {k}: {v}")

    mitre = Counter()
    for e in events:
        for t in e.get("mitre", []):
            mitre[t] += 1

    if mitre:
        print("\nMITRE ATT&CK Coverage by Tactic:")

        techniques_seen = set()
        for e in events:
            for t in e.get("mitre", []):
                techniques_seen.add(t)

        for tactic, techniques in MITRE_TACTICS.items():
            covered = techniques_seen.intersection(techniques)
            if covered:
                print(f"\n{tactic}:")
                for t in sorted(covered):
                    print(f"  - {t}")

        print()
