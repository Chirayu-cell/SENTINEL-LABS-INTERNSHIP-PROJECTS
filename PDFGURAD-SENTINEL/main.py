import os
import json
from datetime import datetime, timezone

from analyzer.pdf_validator import is_valid_pdf
from analyzer.hash_utils import calculate_hashes
from analyzer.metadata_extractor import extract_metadata
from analyzer.structure_scanner import scan_structure
from analyzer.heuristics import apply_heuristics, apply_stream_heuristics
from analyzer.stream_decoder import decode_streams
from analyzer.action_extractor import extract_actions
from analyzer.js_analyzer import analyze_javascript
from analyzer.embedded_extractor import extract_embedded_files
from analyzer.ioc_extractor import extract_iocs_from_js
from analyzer.correlator import correlate
from analyzer.risk_scoring import score_risk, adjust_score_with_reputation
from analyzer.reputation import apply_reputation
from analyzer.virustotal import query_vt_hash

LOG_INGESTION = "logs/ingestion/events.jsonl"
LOG_PRETTY = "logs/pretty/events.json"


def analyze_pdf(file_path: str):
    if not is_valid_pdf(file_path):
        raise ValueError("File is not a valid PDF")

    # ─────────────────────────────
    # Phase 1 — Identity & Structure
    # ─────────────────────────────
    hashes = calculate_hashes(file_path)
    metadata = extract_metadata(file_path)
    structure = scan_structure(file_path)
    flags = apply_heuristics(structure)

    # ─────────────────────────────
    # Phase 1.5 — Streams & Entropy
    # ─────────────────────────────
    stream_data = decode_streams(file_path)
    flags.extend(apply_stream_heuristics(stream_data))

    # ─────────────────────────────
    # Phase 2 — Actions & JS Intent
    # ─────────────────────────────
    actions = extract_actions(file_path)
    js_intent = analyze_javascript(stream_data["javascript_snippets"])

    if actions:
        flags.append("document_action_present")

    if js_intent["suspicious_apis_detected"]:
        flags.append("suspicious_javascript_api_usage")

    # ─────────────────────────────
    # Phase 3 — Embedded Payloads
    # ─────────────────────────────
    embedded_files = extract_embedded_files(file_path)

    if embedded_files:
        flags.append("embedded_payload_detected")

    # ─────────────────────────────
    # Phase 4 — IOCs & Correlation
    # ─────────────────────────────
    iocs = extract_iocs_from_js(stream_data["javascript_snippets"])

    # ─────────────────────────────
    # Assemble event (pre-correlation)
    # ─────────────────────────────
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file_name": os.path.basename(file_path),
        "file_size": os.path.getsize(file_path),
        "hashes": hashes,
        "metadata": metadata,
        "structure": structure,
        "streams": stream_data,
        "actions": actions,
        "javascript_intent": js_intent,
        "embedded_files": embedded_files,
        "iocs": iocs,
        "flags": list(set(flags)),
    }

    # ─────────────────────────────
    # Phase 4 continued — Correlation
    # ─────────────────────────────
    correlations = correlate(event)
    event["correlations"] = correlations

    # ─────────────────────────────
    # Phase 5 — Offline Reputation
    # ─────────────────────────────
    reputation_verdicts = apply_reputation(event)
    event["reputation"] = reputation_verdicts

    # ─────────────────────────────
    # Phase 6 — VirusTotal (hash-only)
    # ─────────────────────────────
    vt_result = query_vt_hash(hashes["sha256"])
    event["virustotal"] = vt_result

    if isinstance(vt_result, dict) and vt_result.get("malicious", 0) > 0:
        flags.append("virustotal_malicious_detection")

    if vt_result.get("error") == "VT query failed (404)":
        flags.append("virustotal_unknown_hash")

    event["flags"] = list(set(flags))

    # ─────────────────────────────
    # Risk Scoring (final)
    # ─────────────────────────────
    base_risk = score_risk(event["flags"])
    final_risk = adjust_score_with_reputation(base_risk, reputation_verdicts)
    event["risk"] = final_risk

    # ─────────────────────────────
    # Logging
    # ─────────────────────────────
    os.makedirs("logs/ingestion", exist_ok=True)
    os.makedirs("logs/pretty", exist_ok=True)

    with open(LOG_INGESTION, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    with open(LOG_PRETTY, "w", encoding="utf-8") as f:
        json.dump(event, f, indent=4)

    print("[+] Analysis complete")
    print(json.dumps(event, indent=4))


if __name__ == "__main__":
    SAMPLE_PDF = "samples/test.pdf"
    analyze_pdf(SAMPLE_PDF)
