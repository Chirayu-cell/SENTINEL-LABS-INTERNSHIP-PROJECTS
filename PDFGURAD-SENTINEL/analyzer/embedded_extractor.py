from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject
import hashlib

def _hash_bytes(data: bytes):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

def extract_embedded_files(file_path):
    reader = PdfReader(file_path)
    embedded = []

    try:
        names = reader.trailer["/Root"].get("/Names")
        if not names or "/EmbeddedFiles" not in names:
            return embedded

        ef_tree = names["/EmbeddedFiles"]
        name_array = ef_tree.get("/Names", [])

        # Structure: [name1, fileSpec1, name2, fileSpec2, ...]
        for i in range(0, len(name_array), 2):
            try:
                filename = str(name_array[i])
                file_spec = name_array[i + 1]

                if isinstance(file_spec, IndirectObject):
                    file_spec = file_spec.get_object()

                ef_dict = file_spec.get("/EF")
                if not ef_dict:
                    continue

                file_stream = ef_dict.get("/F")
                if isinstance(file_stream, IndirectObject):
                    file_stream = file_stream.get_object()

                data = file_stream.get_data()

                embedded.append({
                    "filename": filename,
                    "size": len(data),
                    "hashes": _hash_bytes(data),
                })

            except Exception:
                continue

    except Exception:
        pass

    return embedded
