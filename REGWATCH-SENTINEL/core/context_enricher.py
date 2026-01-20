import socket
import getpass
import platform

def enrich_context(event):
    event["host"] = socket.gethostname()
    event["user"] = getpass.getuser()
    event["os"] = platform.platform()
