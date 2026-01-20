_EVENTS = []

def add_event(event):
    _EVENTS.append(event)

def get_events():
    return _EVENTS

def clear_events():
    _EVENTS.clear()
