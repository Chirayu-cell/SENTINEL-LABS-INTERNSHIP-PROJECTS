def correlate(event):
    correlations = []

    if event.get("actions"):
        correlations.append("document_has_auto_actions")

    if event.get("javascript_intent", {}).get("suspicious_apis_detected"):
        correlations.append("javascript_calls_sensitive_apis")

    if event.get("embedded_files"):
        correlations.append("pdf_carries_embedded_payload")

    high_entropy = any(
        s.get("entropy", 0) > 7.2 for s in event.get("streams", {}).get("streams", [])
    )
    if high_entropy:
        correlations.append("high_entropy_streams_present")

    return correlations
