def sanitize_feed(raw_text: str) -> str:
    clean_lines = []

    for line in raw_text.splitlines():
        line = line.strip()

        if not line:
            continue
        if line.startswith("#"):
            continue
        if "abuse.ch" in line.lower():
            continue
        if line.startswith("http"):
            continue

        clean_lines.append(line)

    return "\n".join(clean_lines)
