from telemetry.event_store import get_events
from collections import Counter
from core.context_enricher import enrich_context

def generate_report():
    events = get_events()

    print("\n=== REGWATCH SENTINEL FINAL DETECTION REPORT ===\n")
    print(f"Total Events Logged: {len(events)}\n")

    severity = Counter(e["severity"] for e in events)
    print("Severity Distribution:")
    for s, c in severity.items():
        print(f"  {s}: {c}")

    print("\nTop High-Risk Events:\n")
    for e in events:
        if e["severity"] == "HIGH":
            print("-" * 45)

            print(f"Registry Path : {e['registry_path']}")
            
            cmd = e.get("new_value", {}).get("data")
            if cmd:
                print(f"Command       : {cmd}")
            
            print(f"Value Name    : {e['value_name']}")
                        
            print(f"User          : {e.get('user', 'N/A')}")
            print(f"Host          : {e.get('host', 'N/A')}")
            print(f"OS            : {e.get('os', 'N/A')}")
            
            print(f"Risk Score    : {e['risk_score']}")
            print("Reasons:")
            for r in e["reasons"]:
                print(f"  - {r}")
            print(f"MITRE        : {', '.join(e['mitre_techniques'])}")
            print()