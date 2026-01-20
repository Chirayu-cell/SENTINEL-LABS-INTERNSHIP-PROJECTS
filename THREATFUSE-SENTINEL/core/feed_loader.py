import requests
from pathlib import Path


def load_local_feed(file_path: str) -> str:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Local feed not found: {file_path}")

    return path.read_text(encoding="utf-8", errors="ignore")


def load_remote_feed(url: str, timeout: int = 10) -> str:
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.text
