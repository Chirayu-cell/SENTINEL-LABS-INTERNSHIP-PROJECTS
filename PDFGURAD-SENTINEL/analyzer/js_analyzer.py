SUSPICIOUS_JS_APIS = [
    "eval",
    "unescape",
    "app.launchURL",
    "this.exportDataObject",
    "util.printf",
    "Collab.collectEmailInfo",
    "getAnnots"
]

def analyze_javascript(js_snippets):
    findings = []
    indicators = []

    for js in js_snippets:
        js_lower = js.lower()
        matched = []

        for api in SUSPICIOUS_JS_APIS:
            if api.lower() in js_lower:
                matched.append(api)

        findings.append({
            "length": len(js),
            "matched_apis": matched
        })

        if matched:
            indicators.extend(matched)

    return {
        "javascript_analysis": findings,
        "suspicious_apis_detected": list(set(indicators))
    }
