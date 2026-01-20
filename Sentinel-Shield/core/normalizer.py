import urllib.parse
import html

def normalize_request(request):
    # URL decode
    decoded = urllib.parse.unquote(request)

    # HTML entity decode
    decoded = html.unescape(decoded)

    # Lowercase
    decoded = decoded.lower()

    return decoded