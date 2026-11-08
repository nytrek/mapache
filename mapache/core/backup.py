"""Backups taken before any registry or scheduled task change.

Files go to %APPDATA%\\Mapache\\backups\\<session>\\. If a backup fails, nothing is deleted.
"""
import re
import subprocess
import time

from ..i18n import t
from ..ui.console import GRN, GRY, YEL
from .paths import APP_DIR
from .proc import run_cmd
from .winreg_util import full_key, reg_flag

BACKUP_DIR = APP_DIR / "backups"
_session = None


def session_dir():
    """One folder per Mapache session."""
    global _session
    if _session is None:
        _session = BACKUP_DIR / time.strftime("%Y%m%d_%H%M%S")
    _session.mkdir(parents=True, exist_ok=True)
    return _session


def _safe(name: str) -> str:
    return re.sub(r"[^\w.-]+", "_", name).strip("_")[:120] or "backup"


def reg_export(hive, path, view, log) -> bool:
    key = full_key(hive, path)
    if log.dry:
        log(t("backup.sim_reg", key=key), GRY)
        return True
    dest = session_dir() / f"{_safe(key)}.reg"
    n = 1
    while dest.exists():
        n += 1
        dest = dest.with_name(f"{_safe(key)}_{n}.reg")
    if run_cmd(["reg", "export", key, str(dest), "/y", *reg_flag(view)], log) == 0 and dest.exists():
        log(t("backup.saved", path=str(dest)), GRN)
        return True
    log(t("backup.failed", what=key), YEL)
    return False


def reg_delete_key(hive, path, view, log) -> bool:
    """Export the key and delete it only if the export succeeded."""
    if not reg_export(hive, path, view, log):
        return False
    return run_cmd(["reg", "delete", full_key(hive, path), "/f", *reg_flag(view)], log) == 0


def reg_delete_value(hive, path, name, view, log) -> bool:
    if not reg_export(hive, path, view, log):
        return False
    return run_cmd(["reg", "delete", full_key(hive, path), "/v", name, "/f", *reg_flag(view)], log) == 0


def task_export(task: str, log) -> bool:
    """Save the XML definition of a scheduled task."""
    if log.dry:
        log(t("backup.sim_task", task=task), GRY)
        return True
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", task, "/XML"], capture_output=True, text=True,
                           errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        r = None
    if not r or r.returncode != 0 or "<Task" not in r.stdout:
        log(t("backup.failed", what=task), YEL)
        return False
    dest = session_dir() / f"task_{_safe(task)}.xml"
    dest.write_text(r.stdout, encoding="utf-16")  # schtasks /Create /XML expects UTF-16
    log(t("backup.saved", path=str(dest)), GRN)
    return True
