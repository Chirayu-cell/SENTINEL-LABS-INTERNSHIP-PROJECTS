from datetime import datetime,timezone

def generate_report(
    feeds_processed: int,
    total_records: int,
    scored_data: dict,
    blocklists: dict
) -> str:

    now = datetime.now(timezone.utc).isoformat()

    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

    for data in scored_data.values():
        severity_counts[data["severity"]] += 1

    line = "=" * 72
    subline = "-" * 72

    report = []

    # --------------------------------------------------
    # Header
    # --------------------------------------------------
    report.append(line)
    report.append(" THREATFUSE SENTINEL — THREAT INTELLIGENCE REPORT")
    report.append(line)
    report.append(f" Generated At        : {now}")
    report.append(f" Feeds Processed     : {feeds_processed}")
    report.append(f" Unique Indicators   : {total_records}")
    report.append("")

    # --------------------------------------------------
    # Severity Summary
    # --------------------------------------------------
    report.append(subline)
    report.append(" SEVERITY DISTRIBUTION")
    report.append(subline)
    report.append(f"   LOW     : {severity_counts['LOW']}")
    report.append(f"   MEDIUM  : {severity_counts['MEDIUM']}")
    report.append(f"   HIGH    : {severity_counts['HIGH']}")
    report.append("")

    # --------------------------------------------------
    # Enforcement Summary
    # --------------------------------------------------
    report.append(subline)
    report.append(" ENFORCEMENT SUMMARY (BLOCKLISTS)")
    report.append(subline)
    report.append(f"   IP ADDRESSES      : {len(blocklists['ip'])}")
    report.append(f"   DOMAINS / URLS    : {len(blocklists['domain'])}")
    report.append(f"   FILE HASHES       : {len(blocklists['hash'])}")
    report.append("")

    # --------------------------------------------------
    # High & Medium Risk Indicators
    # --------------------------------------------------
    report.append(subline)
    report.append(" PRIORITY INDICATORS (MEDIUM / HIGH)")
    report.append(subline)

    found = False

    for (indicator, ioc_type), data in scored_data.items():
        if data["severity"] in {"MEDIUM", "HIGH"}:
           found = True
           report.append(f"   Indicator : {indicator}")
           report.append(f"   Type      : {ioc_type}")
           report.append(f"   Severity  : {data['severity']}")
           report.append(f"   Sources   : {len(data['sources'])}")
           report.append("")

    if not found:
        report.append("   No MEDIUM or HIGH confidence indicators detected.")
        report.append("")

    # --------------------------------------------------
    # Footer
    # --------------------------------------------------
    report.append(subline)
    report.append(" NOTES")
    report.append(subline)
    report.append(" - Severity is based on cross-source correlation.")
    report.append(" - LOW severity indicators are informational only.")
    report.append(" - Blocklists contain MEDIUM and HIGH indicators only.")
    report.append(" - This report is deterministic and explainable.")
    report.append(line)
    report.append("")

    return "\n".join(report)
