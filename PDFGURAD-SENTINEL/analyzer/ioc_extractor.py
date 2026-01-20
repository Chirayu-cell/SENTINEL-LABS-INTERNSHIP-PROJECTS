import re

URL_RE = re.compile(rb'https?://[^\s\'"]+')
IP_RE = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(rb'\b[a-zA-Z0-9.-]+\.(?:com|net|org|io|ru|cn|biz|info)\b')

def extract_iocs_from_js(js_snippets):
    urls, ips, domains = set(), set(), set()

    for js in js_snippets:
        data = js.encode(errors="ignore")
        urls.update(m.decode(errors="ignore") for m in URL_RE.findall(data))
        ips.update(m.decode() for m in IP_RE.findall(data))
        domains.update(m.decode() for m in DOMAIN_RE.findall(data))

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains)
    }
