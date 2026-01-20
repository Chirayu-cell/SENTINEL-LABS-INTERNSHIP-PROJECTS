import os
import hashlib

def hash_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def validate_executable(path):
    result = {
        "exists": False,
        "sha256": None
    }

    if os.path.isfile(path):
        result["exists"] = True
        result["sha256"] = hash_file(path)

    return result
