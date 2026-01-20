def apply_heuristics(structure_data):
    flags = []

    indicators = structure_data["indicators"]

    if indicators["/JavaScript"] or indicators["/JS"]:
        flags.append("javascript_present")

    if indicators["/EmbeddedFile"]:
        flags.append("embedded_file_present")

    if indicators["/Launch"]:
        flags.append("launch_action_present")

    if structure_data["object_count"] > 500:
        flags.append("high_object_count")

    return flags

def apply_stream_heuristics(stream_data):
    flags = []

    for stream in stream_data["streams"]:
        if stream["entropy"] > 7.2:
            flags.append("high_entropy_stream")

    if stream_data["javascript_snippets"]:
        flags.append("javascript_content_detected")

    return flags
