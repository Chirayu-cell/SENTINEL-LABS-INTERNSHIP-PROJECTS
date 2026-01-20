from PyPDF2 import PdfReader
from PyPDF2.generic import DictionaryObject

def extract_actions(file_path):
    reader = PdfReader(file_path)

    actions = []

    # Document-level OpenAction
    try:
        catalog = reader.trailer["/Root"]
        if "/OpenAction" in catalog:
            actions.append({
                "type": "OpenAction",
                "object": str(catalog["/OpenAction"])
            })
    except Exception:
        pass

    # Page-level Additional Actions
    for i, page in enumerate(reader.pages):
        try:
            if "/AA" in page:
                aa = page["/AA"]
                for action_type, action_obj in aa.items():
                    actions.append({
                        "type": f"Page_{i}_{action_type}",
                        "object": str(action_obj)
                    })
        except Exception:
            continue

    return actions
