import re

SUSPICIOUS_KEYWORDS = [
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/ObjStm"
]

def scan_structure(file_path):
    findings = {key.decode(): False for key in SUSPICIOUS_KEYWORDS}
    object_count = 0

    with open(file_path, "rb") as f:
        data = f.read()

    object_count = len(re.findall(rb"\d+\s+\d+\s+obj", data))

    for key in SUSPICIOUS_KEYWORDS:
        if key in data:
            findings[key.decode()] = True

    return {
        "object_count": object_count,
        "indicators": findings
    }
