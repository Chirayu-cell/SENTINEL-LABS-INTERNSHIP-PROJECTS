import os
import json
import time
import requests
from pathlib import Path

VT_URL = "https://www.virustotal.com/api/v3/files/"
CACHE_FILE = Path("intel/vt_cache.json")
CACHE_TTL = 24 * 60 * 60  # 24 hours

def _load_cache():
    if CACHE_FILE.exists():
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def _save_cache(cache):
    CACHE_FILE.parent.mkdir(exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def query_vt_hash(sha256):
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"error": "VT_API_KEY not set"}

    cache = _load_cache()
    now = int(time.time())

    if sha256 in cache:
        entry = cache[sha256]
        if now - entry["timestamp"] < CACHE_TTL:
            return entry["result"]

    headers = {"x-apikey": api_key}
    resp = requests.get(VT_URL + sha256, headers=headers)

    if resp.status_code != 200:
        return {"error": f"VT query failed ({resp.status_code})"}

    data = resp.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    result = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "source": "virustotal"
    }

    cache[sha256] = {
        "timestamp": now,
        "result": result
    }
    _save_cache(cache)

    return result
