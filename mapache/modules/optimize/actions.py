"""Reversible actions for the optimize module (registered in engine.KINDS).

StartupOff writes the same StartupApproved value as Task Manager. TaskOff toggles a scheduled task.
PowerPlan switches the active power scheme.
"""
import json
import re
import subprocess

from ...core.proc import powershell, run_cmd
from ..harden import engine
from ..harden.engine import RegValue

ENABLED_HEX = "02" + "00" * 11
DISABLED_HEX = "03" + "00" * 11  # Windows only reads the first byte; the rest is an optional timestamp


class StartupOff(RegValue):
    kind = "startup"

    def __init__(self, hive: str, path: str, name: str, view: int = None):
        super().__init__(hive, path, name, "REG_BINARY", DISABLED_HEX, view)

    def params(self):
        return dict(hive=self.hive, path=self.path, name=self.name, view=self.view)

    def describe(self):
        return f"StartupApproved {self.hive}\\…\\{self.path.rsplit(chr(92), 1)[-1]}\\{self.name} = 03 (off)"

    def is_applied(self, state=None):
        st = state if state is not None else self.read()
        v = str(st.get("value") or "") if st.get("exists") else ""
        try:
            return bool(v) and int(v[:2], 16) & 1 == 1  # 03 / 01 / 07 = disabled
        except ValueError:
            return False


# --- Scheduled tasks ---
_tasks = {}

TASKS_PS = (
    "@(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | "
    "ForEach-Object { [ordered]@{ Path = $_.TaskPath; Name = $_.TaskName; State = [string]$_.State; "
    "Author = [string]$_.Author; Exec = (@($_.Actions | ForEach-Object { [string]$_.Execute + ' ' + "
    "[string]$_.Arguments }) -join ' | ') } }) | ConvertTo-Json -Compress -Depth 3")


def task_list(refresh=False) -> list:
    """Tasks outside \\Microsoft\\, cached per session."""
    if refresh or "list" not in _tasks:
        try:
            out = powershell(TASKS_PS, timeout=120).stdout.strip()
            data = json.loads(out) if out else []
            _tasks["list"] = data if isinstance(data, list) else [data]
        except (OSError, ValueError, subprocess.TimeoutExpired):
            _tasks["list"] = []
    return _tasks["list"]


class TaskOff(engine.Action):
    kind = "task"

    def __init__(self, tn: str):
        self.tn = tn  # full path: \Folder\Name

    def params(self):
        return dict(tn=self.tn)

    def describe(self):
        return f"schtasks /Change /TN \"{self.tn}\" /DISABLE"

    def read(self):
        for d in task_list():
            if (d.get("Path") or "\\") + (d.get("Name") or "") == self.tn:
                return {"state": d.get("State")}
        # not cached (e.g. undo in a later session): query this task only
        path, _, name = self.tn.rpartition("\\")
        r = powershell("[string](Get-ScheduledTask -TaskPath $env:MAPACHE_TP -TaskName $env:MAPACHE_TN "
                       "-ErrorAction SilentlyContinue).State", env={"MAPACHE_TP": path + "\\", "MAPACHE_TN": name})
        return {"state": (r.stdout or "").strip() or None}

    def is_applied(self, state=None):
        return (state if state is not None else self.read()).get("state") == "Disabled"

    def _set(self, enable, log):
        ok = run_cmd(["schtasks", "/Change", "/TN", self.tn, "/ENABLE" if enable else "/DISABLE"], log) == 0
        if ok and not log.dry:
            task_list(refresh=True)
        return ok

    def apply(self, log):
        return self._set(False, log)

    def revert(self, before, log):
        st = before.get("state")
        if st in (None, "Disabled"):  # was disabled already, or no longer exists
            return True
        return self._set(True, log)


# --- Power plan ---
GUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
POWER_SAVER = "a1841308-3541-4fab-bc81-f71556f20b4a"
BALANCED = "381b4222-f694-41f0-9685-ff5bb260df2e"


def _powercfg(*args) -> str:
    try:
        return subprocess.run(["powercfg", *args], capture_output=True, text=True, errors="replace",
                              timeout=30).stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def active_scheme() -> str:
    m = GUID_RE.search(_powercfg("/getactivescheme"))
    return m.group(0).lower() if m else ""


def schemes() -> set:
    return {g.lower() for g in GUID_RE.findall(_powercfg("/list"))}


class PowerPlan(engine.Action):
    """Activate `guid`. With `avoid`, any active plan other than `avoid` counts as applied."""
    kind = "power"

    def __init__(self, guid: str, avoid: str = None):
        self.guid, self.avoid = guid.lower(), (avoid or "").lower() or None

    def params(self):
        return dict(guid=self.guid, avoid=self.avoid)

    def describe(self):
        return f"powercfg /setactive {self.guid}"

    def read(self):
        return {"active": active_scheme() or None}

    def is_applied(self, state=None):
        cur = (state if state is not None else self.read()).get("active")
        if cur is None:
            return True  # unreadable: not offered
        return cur != self.avoid if self.avoid else cur == self.guid

    def apply(self, log):
        return run_cmd(["powercfg", "/setactive", self.guid], log) == 0

    def revert(self, before, log):
        prev = before.get("active")
        if not prev:
            return True
        if prev not in schemes():  # the previous plan no longer exists
            return False
        return run_cmd(["powercfg", "/setactive", prev], log) == 0


def has_battery() -> bool:
    """True unless the system reports no battery (BatteryFlag 128)."""
    try:
        import ctypes

        class SPS(ctypes.Structure):
            _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte),
                        ("BatteryLifePercent", ctypes.c_ubyte), ("SystemStatusFlag", ctypes.c_ubyte),
                        ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]
        s = SPS()
        if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(s)):
            return True  # unknown: assume laptop
        return s.BatteryFlag != 128  # 255 = unknown
    except (AttributeError, OSError):
        return True


engine.KINDS.update({c.kind: c for c in (StartupOff, TaskOff, PowerPlan)})
