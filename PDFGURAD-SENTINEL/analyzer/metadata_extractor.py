from PyPDF2 import PdfReader

def extract_metadata(file_path):
    reader = PdfReader(file_path)
    meta = reader.metadata or {}

    return {
        "pdf_version": reader.pdf_header,
        "creator": meta.get("/Creator"),
        "producer": meta.get("/Producer"),
        "created": meta.get("/CreationDate"),
        "modified": meta.get("/ModDate"),
        "pages": len(reader.pages)
    }
