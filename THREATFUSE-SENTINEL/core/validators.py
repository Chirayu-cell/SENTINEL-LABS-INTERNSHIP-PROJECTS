import ipaddress
import re


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    if value.startswith("-") or value.endswith("-"):
        return False

    labels = value.split(".")
    for label in labels:
        if not label or label.startswith("-") or label.endswith("-"):
            return False
        if len(label) > 63:
            return False
    return True


def is_valid_hash(value: str) -> bool:
    lengths = {32, 40, 64}  # MD5, SHA1, SHA256
    return len(value) in lengths and value.isalnum()
