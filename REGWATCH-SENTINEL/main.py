from core.registry_scanner import scan_registry
from core.baseline_manager import load_or_create_baseline
from core.change_detector import detect_registry_changes
from core.risk_engine import enrich_events
from telemetry.event_store import get_events, clear_events
from reporting.logger import write_logs
from reporting.report_generator import generate_report

BASELINE_PATH = "baseline/registry_baseline.json"

def main():
    clear_events()

    baseline = load_or_create_baseline(BASELINE_PATH)
    current_snapshot = scan_registry()

    detect_registry_changes(BASELINE_PATH, current_snapshot)
    enrich_events()

    write_logs()
    generate_report()

if __name__ == "__main__":
    main()

