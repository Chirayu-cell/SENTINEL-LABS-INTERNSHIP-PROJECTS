import time
import re
from sentinelshield import handle_request

LOG_FILE = "/var/log/apache2/sentinelshield_access.log"

# Apache combined log regex
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[[^\]]+\] '
    r'"(?P<method>\S+) (?P<request>[^"]+)"'
)

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def main():
    print("[*] SentinelShield log ingestion started...")
    with open(LOG_FILE, "r") as f:
        for line in follow(f):
            match = LOG_PATTERN.search(line)
            if not match:
                continue

            ip = match.group("ip")
            request = match.group("request")

            # Ignore static files
            if any(request.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".ico"]):
                continue

            handle_request(ip, request)

if __name__ == "__main__":
    main()