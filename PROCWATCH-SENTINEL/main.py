# main.py

from core.process_monitor import scan_processes
from core.service_audit import scan_services
from core.relationship_analyzer import analyze_relationships
from core.persistence_monitor import scan_run_keys, scan_startup_folders

from detection.rules import apply_rules
from telemetry.event_store import get_events
from reporting.logger import write_logs
from reporting.report_generator import generate_report


def main():
    # -------------------------
    # Telemetry collection
    # -------------------------
    scan_processes()

    try:
        scan_services()
    except Exception:
        pass  # Service enumeration may fail on restricted systems

    try:
        scan_run_keys()
        scan_startup_folders()
    except Exception:
        pass  # Persistence access may be denied

    # -------------------------
    # Enrichment & correlation
    # -------------------------
    analyze_relationships()

    # -------------------------
    # Detection logic
    # -------------------------
    events = get_events()
    apply_rules(events)

    # -------------------------
    # Logging & reporting
    # -------------------------
    write_logs(events)
    generate_report()


if __name__ == "__main__":
    main()
