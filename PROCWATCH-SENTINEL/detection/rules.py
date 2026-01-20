import json
from telemetry.event_store import add_event

# -----------------------------
# Load policies
# -----------------------------
with open("detection/policy/blacklist.json") as f:
    BLACKLIST = set(x.lower() for x in json.load(f))

# -----------------------------
# Detection constants
# -----------------------------
DUAL_USE = {"powershell.exe", "cmd.exe", "wmic.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe"}
SYSTEM_PATH = "c:\\windows\\system32"

# -----------------------------
# Main detection engine
# -----------------------------
def apply_rules(events):
    """
    Applies risk-based and behavior-based detection rules
    over collected telemetry events.
    """

    # Build PID → process lookup for ancestry analysis
    process_map = {
        e["details"]["pid"]: e["details"]
        for e in events if e["event_type"] == "PROCESS_DETECTED"
    }

    for e in events:

        # ==========================================================
        # PROCESS RISK EVALUATION
        # ==========================================================
        if e["event_type"] == "PROCESS_DETECTED":

            risk = 5
            factors = []
            mitre = []

            details = e["details"]
            name = (details.get("name") or "").lower()
            exe = (details.get("exe") or "").lower()
            ppid = details.get("ppid")
            signed = details.get("signed")

            # --- Dual-use command interpreters ---
            if name in DUAL_USE:
                risk += 15
                factors.append("Dual-use command-line binary")
                mitre.append("T1059")  # Command & Scripting Interpreter

            # --- Explicit blacklist ---
            if name in BLACKLIST:
                risk += 60
                factors.append("Blacklisted binary")
                mitre.append("T1059")

            # --- Unsigned executable ---
            if signed is False:
                risk += 30
                factors.append("Unsigned executable")
                mitre.extend([
                    "T1036",       # Masquerading
                    "T1553.002"    # Code signing abuse
                ])

            # --- Parent process analysis ---
            parent = process_map.get(ppid, {})
            parent_name = (parent.get("name") or "").lower()

            if parent_name in OFFICE:
                risk += 30
                factors.append(f"Launched by Office application ({parent_name})")
                mitre.append("T1204")  # User Execution

            if parent_name == "svchost.exe":
                risk += 40
                factors.append("Spawned by system service (svchost.exe)")
                mitre.append("T1543.003")  # Windows Service abuse

            # --- Non-system execution path ---
            if exe and SYSTEM_PATH not in exe:
                risk += 20
                factors.append("Executed outside Windows system directory")
                mitre.append("T1036")

            # --- Emit elevated-risk process event ---
            if risk >= 40:
                add_event(
                    source="rules",
                    event_type="PROCESS_RISK_ELEVATED",
                    details=details,
                    risk_score=min(risk, 100),
                    risk_factors=factors,
                    mitre=list(set(mitre))  # deduplicate techniques
                )

        # ==========================================================
        # SERVICE RISK EVALUATION
        # ==========================================================
        if e["event_type"] == "SERVICE_DETECTED":

            risk = 10
            factors = []
            mitre = []

            details = e["details"]
            start_type = details.get("start_type")
            binpath = (details.get("binpath") or "").lower()

            # --- Auto-start service ---
            if start_type == "auto":
                risk += 30
                factors.append("Auto-start service")

            # --- Non-system service binary ---
            if binpath and SYSTEM_PATH not in binpath:
                risk += 30
                factors.append("Service binary outside system directory")
                mitre.append("T1543.003")  # Windows Service

            # --- Emit suspicious service event ---
            if risk >= 50:
                add_event(
                    source="rules",
                    event_type="SUSPICIOUS_SERVICE",
                    details=details,
                    risk_score=min(risk, 100),
                    risk_factors=factors,
                    mitre=mitre
                )
