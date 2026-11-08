"""Read-only registry helpers and installed program entries.

Writes go through reg.exe in core/backup.py.
"""
try:
    import winreg
except ImportError:  # allows importing outside Windows (tests)
    winreg = None

UNINSTALL = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"


class CIDict(dict):
    """Dict with case-insensitive keys, matching registry value name semantics."""

    def __init__(self, data=None):
        super().__init__()
        self._k = {}
        for k, v in (data or {}).items():
            self[k] = v

    def __setitem__(self, k, v):
        old = self._k.get(str(k).lower())
        if old is not None and old != k:
            super().__delitem__(old)
        self._k[str(k).lower()] = k
        super().__setitem__(k, v)

    def __getitem__(self, k):
        return super().__getitem__(self._k.get(str(k).lower(), k))

    def __contains__(self, k):
        return str(k).lower() in self._k

    def get(self, k, default=None):
        return self[k] if k in self else default


def hives():
    """(hive, view) of the three uninstall registry branches."""
    if winreg is None:
        return []
    return [(winreg.HKEY_CURRENT_USER, 0),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)]


def hive_name(hive) -> str:
    if winreg is None:
        return "?"
    return {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM",
            winreg.HKEY_USERS: "HKU", winreg.HKEY_CLASSES_ROOT: "HKCR"}.get(hive, "?")


def reg_flag(view) -> list:
    """reg.exe flag for the same registry view used by winreg."""
    if winreg is None or not view:
        return []
    return ["/reg:64"] if view == winreg.KEY_WOW64_64KEY else ["/reg:32"]


def full_key(hive, path) -> str:
    return f"{hive_name(hive)}\\{path}"


def reg_values(hive, path, view=0) -> dict:
    out = CIDict()
    if winreg is None:
        return out
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = val
                i += 1
    except OSError:
        pass
    return out


def reg_subkeys(hive, path, view=0) -> list:
    subs = []
    if winreg is None:
        return subs
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
            i = 0
            while True:
                try:
                    subs.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return subs


def reg_get(hive, path, name, default=None, view=0):
    return reg_values(hive, path, view).get(name, default)


REG_TYPES = {}
if winreg is not None:
    REG_TYPES = {winreg.REG_DWORD: "REG_DWORD", winreg.REG_QWORD: "REG_QWORD", winreg.REG_SZ: "REG_SZ",
                 winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ", winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
                 winreg.REG_BINARY: "REG_BINARY"}


def reg_value_typed(hive, path, name, view=0):
    """(value, type name) or None if the value does not exist."""
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
            val, typ = winreg.QueryValueEx(k, name)
        return val, REG_TYPES.get(typ, str(typ))
    except OSError:
        return None


def key_exists(hive, path, view=0) -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view):
            return True
    except OSError:
        return False


def key_mtime(hive, path, view=0) -> float:
    """Key last write time (fallback install date)."""
    if winreg is None:
        return 0.0
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as k:
            ft = winreg.QueryInfoKey(k)[2]  # FILETIME: 100 ns intervals since 1601
        return ft / 1e7 - 11644473600 if ft else 0.0
    except OSError:
        return 0.0


def arp_entries() -> list:
    out = []
    for hive, view in hives():
        for sub in reg_subkeys(hive, UNINSTALL, view):
            v = {k: str(x) for k, x in reg_values(hive, f"{UNINSTALL}\\{sub}", view).items()}
            if v.get("DisplayName"):
                v["_hive"], v["_view"], v["_key"], v["_sub"] = hive, view, f"{UNINSTALL}\\{sub}", sub
                out.append(v)
    return out
