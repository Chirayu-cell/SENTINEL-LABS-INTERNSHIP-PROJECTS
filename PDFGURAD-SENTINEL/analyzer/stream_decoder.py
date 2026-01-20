from PyPDF2 import PdfReader
from analyzer.entropy import shannon_entropy

def decode_streams(file_path):
    reader = PdfReader(file_path)

    decoded_streams = []
    javascript_snippets = []

    for page in reader.pages:
        try:
            contents = page.get_contents()

            if not contents:
                continue

            # contents can be a list or single object
            content_objs = contents if isinstance(contents, list) else [contents]

            for obj in content_objs:
                try:
                    raw = obj.get_data()
                    entropy = shannon_entropy(raw)

                    decoded_streams.append({
                        "length": len(raw),
                        "entropy": entropy
                    })

                    if b"/JavaScript" in raw or b"/JS" in raw:
                        javascript_snippets.append(
                            raw[:500].decode(errors="ignore")
                        )

                except Exception:
                    continue

        except Exception:
            continue

    return {
        "streams": decoded_streams,
        "javascript_snippets": javascript_snippets
    }
