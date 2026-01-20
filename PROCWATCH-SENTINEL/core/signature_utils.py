def is_binary_signed(path):
    """
    Returns:
      True  -> binary is signed
      False -> binary is unsigned
      None  -> signature status unavailable
    """

    if not path:
        return None

    try:
        import importlib
        win32trust = importlib.import_module("win32trust")
        win32api = importlib.import_module("win32api")

        win32trust.WinVerifyTrust(
            None,
            win32trust.WINTRUST_ACTION_GENERIC_VERIFY_V2,
            {
                "FileInfo": {
                    "FilePath": path,
                    "FileHandle": None,
                    "KnownSubject": None
                },
                "UIChoice": win32trust.WTD_UI_NONE,
                "RevocationChecks": win32trust.WTD_REVOKE_NONE,
                "UnionChoice": win32trust.WTD_CHOICE_FILE,
                "StateAction": win32trust.WTD_STATEACTION_VERIFY,
                "ProvFlags": win32trust.WTD_SAFER_FLAG,
            }
        )
        return True

    except ImportError:
        # pywin32 not installed or unsupported Python version
        return None

    except Exception:
        # Verification attempted but failed
        return False
