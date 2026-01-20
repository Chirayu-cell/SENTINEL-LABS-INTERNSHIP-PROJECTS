from pathlib import Path


def load_feed_list(feed_file: Path) -> list:
    feeds = []

    with feed_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue
            if line.startswith("#"):
                continue

            feeds.append(line)

    return feeds
