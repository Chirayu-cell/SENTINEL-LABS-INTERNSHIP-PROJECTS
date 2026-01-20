import re
from core.validators import is_valid_ip, is_valid_domain, is_valid_hash


def parse_iocs(raw_text: str) -> dict:
    results = {
        "ip": set(),
        "domain": set(),
        "hash": set(),
    }

    ip_candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_text)
    domain_candidates = re.findall(r"(?<![-\w])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+",raw_text)
    hash_candidates = re.findall(r"\b[a-fA-F0-9]{32,64}\b", raw_text)

    for ip in ip_candidates:
        if is_valid_ip(ip):
            results["ip"].add(ip)

    for domain in domain_candidates:
        if is_valid_domain(domain):
            results["domain"].add(domain)

    for h in hash_candidates:
        if is_valid_hash(h):
            results["hash"].add(h)

    return results
