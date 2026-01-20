import os
import winreg
from telemetry.event_store import add_event

TRUSTED_RUN_KEY_NAMES = {
    "OneDrive",
    "Steam",
    "Discord",
    "Spotify",
    "SecurityHealth",
    "MicrosoftEdgeAutoLaunch"
}

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run")
]

STARTUP_DIRS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
]

def scan_run_keys():
    for hive, path in RUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                name, value, _ = winreg.EnumValue(key, i)
                risk = 70
                factors = ["Auto-start registry key"]

                if name in TRUSTED_RUN_KEY_NAMES:
                    risk = 25
                    factors.append("Known trusted auto-start application")

                add_event(
                    source="persistence_monitor",
                    event_type="REGISTRY_RUN_KEY",
                    details={"name": name, "value": value},
                    risk_score=risk,
                    risk_factors=factors,
                    mitre=["T1547.001"]
                )
                i += 1
        except OSError:
            pass

def scan_startup_folders():
    for folder in STARTUP_DIRS:
        if not os.path.isdir(folder):
            continue
        for f in os.listdir(folder):
            add_event(
                source="persistence_monitor",
                event_type="STARTUP_FOLDER_PERSISTENCE",
                details={"file": f, "path": folder},
                risk_score=65,
                risk_factors=["Startup folder persistence"],
                mitre=["T1547.009"]  # Startup Folder
            )

