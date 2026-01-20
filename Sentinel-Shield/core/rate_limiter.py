import time

request_log = {}

def check_rate_limit(ip, limit=5, window=10):
    now = time.time()
    request_log.setdefault(ip, [])
    request_log[ip] = [t for t in request_log[ip] if now - t < window]
    request_log[ip].append(now)

    if len(request_log[ip]) > limit:
        return True
    return False