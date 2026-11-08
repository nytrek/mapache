"""Administrator privileges."""
import os
import subprocess
import sys
from pathlib import Path


def is_admin() -> bool:
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_admin(extra_args: list) -> bool:
    """Relaunch elevated (UAC prompt) in a new window."""
    root = Path(__file__).resolve().parents[2]  # folder that contains the mapache package
    params = subprocess.list2cmdline(["-m", "mapache", *extra_args, "--elevated"])
    try:
        import ctypes
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(root), 1)
    except Exception:
        return False
    return r > 32
