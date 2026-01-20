import winreg
import json

CONFIG_PATH = "config/monitored_keys.json"

HIVE_MAP = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE
}

def read_key(hive, path):
    data = {}
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, vtype = winreg.EnumValue(key, i)
                    data[name] = {
                        "data": value,
                        "type": winreg.QueryValueEx(key, name)[1]
                    }
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    return data

def scan_registry():
    with open(CONFIG_PATH) as f:
        monitored = json.load(f)

    snapshot = {}

    for entry in monitored:
        hive_name, reg_path = entry.split("\\", 1)
        hive = HIVE_MAP[hive_name]
        snapshot[entry] = read_key(hive, reg_path)

    return snapshot
