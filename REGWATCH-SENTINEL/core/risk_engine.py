import os
import shlex
from telemetry.event_store import get_events
from core.context_enricher import enrich_context
from core.executable_validator import validate_executable

SYSTEM_BINARIES = [
    "svchost.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "services.exe", "explorer.exe"
]

LOLBINS = [
    "powershell.exe", "cmd.exe",
    "wmic.exe", "rundll32.exe"
]

USER_WRITABLE_PATHS = ["appdata", "temp", "downloads"]


def assess_risk(event):
    score = 0
    reasons = []
    mitre = set()

    # --- Registry context ---
    reg_path = event["registry_path"].lower()
    raw_data = (event.get("new_value", {}) or {}).get("data", "")
    raw_data = raw_data.lower() if isinstance(raw_data, str) else ""

    # --- Parse executable safely (Windows-aware) ---
    try:
        parts = shlex.split(raw_data, posix=False)
        exe_path = parts[0] if parts else ""
    except ValueError:
        exe_path = ""

    filename = os.path.basename(exe_path)

    # --- Executable validation ---
    validation = validate_executable(exe_path)
    event["executable"] = validation
    event["parsed_executable"] = exe_path

    if not validation["exists"]:
        score += 20
        reasons.append("Referenced executable does not exist on disk")
        mitre.add("T1105")  # Ingress Tool Transfer (likely dropped later)

    # --- Registry modification always applies ---
    mitre.add("T1112")

    # --- Autorun persistence ---
    if "currentversion\\run" in reg_path:
        score += 30
        reasons.append("Autorun registry persistence")
        mitre.add("T1547.001")

    # --- User-writable execution path ---
    if any(p in raw_data for p in USER_WRITABLE_PATHS):
        score += 30
        reasons.append("Executable in user-writable directory")

    # --- LOLBIN presence ---
    if any(bin in raw_data for bin in LOLBINS):
        score += 20
        reasons.append("LOLBIN referenced in persistence")
        mitre.add("T1059")

    # --- Command execution via registry ---
    if "cmd.exe" in raw_data and "/c" in raw_data:
        score += 20
        reasons.append("Command execution via registry persistence")
        mitre.add("T1059")

    # --- Masquerading detection ---
    if filename in SYSTEM_BINARIES and "system32" not in exe_path:
        score += 40
        reasons.append("Masquerading as Windows system binary")
        mitre.add("T1036")

    # --- System-wide persistence ---
    if reg_path.startswith("hklm"):
        score += 10
        reasons.append("System-wide persistence")

    # --- Cap score to avoid runaway escalation ---
    score = min(score, 100)

    # --- Severity mapping ---
    if score >= 61:
        severity = "HIGH"
    elif score >= 31:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # --- Deduplicate reasons (clean output) ---
    reasons = list(dict.fromkeys(reasons))

    # --- Final event update ---
    event.update({
        "risk_score": score,
        "severity": severity,
        "reasons": reasons,
        "mitre_techniques": sorted(mitre)
    })


def enrich_events():
    for event in get_events():
        assess_risk(event)
        enrich_context(event)
