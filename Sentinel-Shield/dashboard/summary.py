import json
import os
from collections import Counter, defaultdict

# Resolve project root safely
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "sentinelshield.log")


def load_logs():
    logs = []
    if not os.path.exists(LOG_FILE):
        print("[!] sentinelshield.log not found")
        return logs

    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return logs


def main():
    logs = load_logs()
    if not logs:
        print("[!] No logs to analyze")
        return

    decision_counter = Counter()
    attack_counter = Counter()
    ip_reputation = defaultdict(str)
    ip_attack_count = defaultdict(int)

    for entry in logs:
        # Decisions
        decision = entry.get("decision", "UNKNOWN")
        decision_counter[decision] += 1

        # Attack types
        for attack in entry.get("detections", []):
            attack_counter[attack] += 1

        # IP reputation (FIXED FIELD NAME)
        ip = entry.get("ip")
        reputation = entry.get("log_ip_reputation", "CLEAN")
        ip_reputation[ip] = reputation

        # Count malicious activity per IP
        if entry.get("detections"):
            ip_attack_count[ip] += 1

    # Categorize IPs
    malicious_ips = [ip for ip, rep in ip_reputation.items() if rep == "MALICIOUS"]
    suspicious_ips = [ip for ip, rep in ip_reputation.items() if rep == "SUSPICIOUS"]

    # Output summary
    print("\n=== SentinelShield SOC Summary ===\n")

    print("Decisions:")
    for d, count in decision_counter.items():
        print(f"  {d}: {count}")

    print("\nAttack Types:")
    for a, count in attack_counter.items():
        print(f"  {a}: {count}")

    print("\nIP Reputation Summary:")
    print(f"  MALICIOUS IPs: {len(malicious_ips)}")
    print(f"  SUSPICIOUS IPs: {len(suspicious_ips)}")

    if malicious_ips:
        print("\nMalicious IPs Detected:")
        for ip in malicious_ips:
            print(f"  {ip}  (attacks: {ip_attack_count[ip]})")

    if suspicious_ips:
        print("\nSuspicious IPs Detected:")
        for ip in suspicious_ips:
            print(f"  {ip}  (attacks: {ip_attack_count[ip]})")

    print("\n=== End of Summary ===\n")


if __name__ == "__main__":
    main()