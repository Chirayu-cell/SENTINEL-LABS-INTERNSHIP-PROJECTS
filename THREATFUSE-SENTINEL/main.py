from pathlib import Path

from core.feed_loader import load_local_feed, load_remote_feed
from core.feed_registry import load_feed_list
from core.feed_sanitizer import sanitize_feed
from core.ioc_parser import parse_iocs
from core.normalizer import normalize_iocs
from core.correlator import correlate_iocs
from core.severity import assign_severity
from core.blocklist import generate_blocklists, export_blocklist
from reporting.report_generator import generate_report

BASE_DIR = Path(__file__).resolve().parent


def main():
    #print("=== THREATFUSE SENTINEL :: CONFIG-DRIVEN RUN ===")

    # -----------------------------
    # Local feeds (optional)
    # -----------------------------
    local_feeds = [
        ("local_sample_1", BASE_DIR / "feeds" / "local" / "sample.txt"),
        ("local_sample_2", BASE_DIR / "feeds" / "local" / "sample2.txt"),
        ("local_sample_3", BASE_DIR / "feeds" / "local" / "sample3.txt")
    ]

    # -----------------------------
    # Remote feeds (config-driven)
    # -----------------------------
    feed_list_file = BASE_DIR / "feeds" / "remote" / "threat-intelligence.txt"
    remote_urls = load_feed_list(feed_list_file)

    all_records = []

    # Process local feeds
    for source, path in local_feeds:
        raw = load_local_feed(str(path))
        raw = sanitize_feed(raw)
        parsed = parse_iocs(raw)
        normalized = normalize_iocs(parsed, source=source)
        all_records.extend(normalized)

    # Process remote feeds
    for url in remote_urls:
        source = url.split("/")[2]  # domain as source name
        try:
            raw = load_remote_feed(url)
            raw = sanitize_feed(raw)
            parsed = parse_iocs(raw)
            normalized = normalize_iocs(parsed, source=source)
            all_records.extend(normalized)
        except Exception as e:
            print(f"[!] Failed to load feed {url}: {e}")

    # -----------------------------
    # Intelligence pipeline
    # -----------------------------
    correlated = correlate_iocs(all_records)
    scored = assign_severity(correlated)
    blocklists = generate_blocklists(scored)

    # -----------------------------
    # Export blocklists
    # -----------------------------
    output_dir = BASE_DIR / "data" / "blocklists"
    export_blocklist(blocklists["ip"], output_dir / "ip_blocklist.txt")
    export_blocklist(blocklists["domain"], output_dir / "domain_blocklist.txt")
    export_blocklist(blocklists["hash"], output_dir / "hash_blocklist.txt")

    # -----------------------------
    # Reporting
    # -----------------------------
    report = generate_report(
        feeds_processed=len(local_feeds) + len(remote_urls),
        total_records=len(scored),
        scored_data=scored,
        blocklists=blocklists
    )

    print("\n" + report)


if __name__ == "__main__":
    main()
