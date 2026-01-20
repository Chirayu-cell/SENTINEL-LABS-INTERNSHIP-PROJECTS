def is_valid_pdf(file_path):
    try:
        with open(file_path, "rb") as f:
            header = f.read(1024)
            return b"%PDF-" in header
    except Exception:
        return False
