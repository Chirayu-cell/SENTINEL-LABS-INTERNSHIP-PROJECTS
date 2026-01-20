from pathlib import Path

def generate_blocklists(scored_data: dict) -> dict:
    blocklists = {
        "ip": set(),
        "domain": set(),
        "hash": set(),
    }

    for (indicator, ioc_type), data in scored_data.items():
        if data["severity"] in {"MEDIUM", "HIGH"}:
            if ioc_type in blocklists:
                blocklists[ioc_type].add(indicator)

    return blocklists

def export_blocklist(values: set, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for value in sorted(values):
            f.write(value + "\n")