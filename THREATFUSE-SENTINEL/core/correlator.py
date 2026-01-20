from collections import defaultdict


def correlate_iocs(normalized_records: list) -> dict:
    correlation_map = defaultdict(lambda: {
        "type": None,
        "sources": set(),
        "count": 0,
        "first_seen": None,
        "last_seen": None
    })

    for record in normalized_records:
        key = (record["indicator"], record["type"])
        entry = correlation_map[key]

        entry["type"] = record["type"]
        entry["sources"].add(record["source"])
        entry["count"] = len(entry["sources"])

        if entry["first_seen"] is None or record["first_seen"] < entry["first_seen"]:
            entry["first_seen"] = record["first_seen"]

        if entry["last_seen"] is None or record["last_seen"] > entry["last_seen"]:
            entry["last_seen"] = record["last_seen"]

    return correlation_map
