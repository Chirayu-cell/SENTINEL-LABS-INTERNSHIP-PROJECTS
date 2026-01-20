from datetime import datetime,timezone

def normalize_iocs(parsed_iocs: dict, source: str) -> list:
    normalized = []
    timestamp = datetime.now(timezone.utc).isoformat()

    for ioc_type, values in parsed_iocs.items():
        for indicator in values:
            record = {
                "indicator": indicator,
                "type": ioc_type,
                "source": source,
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
            normalized.append(record)

    return normalized
