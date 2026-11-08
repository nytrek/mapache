"""Processes: run commands, detect running programs and close them."""
import json
import os
import subprocess
import time

from ..i18n import t
from ..ui.console import GRY, R, YEL


def run_cmd(cmd, log, live: bool = False, timeout=None) -> int:
    shown = cmd if isinstance(cmd, str) else subprocess.list2cmdline(cmd)
    if log.dry:
        log(t("proc.sim_run", cmd=shown), GRY)
        return 0
    log(f"$ {shown}", GRY)
    try:
        if live:
            r = subprocess.run(cmd, timeout=timeout)
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
            if r.returncode != 0:
                for line in ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[-3:]:
                    log(f"  {line}", GRY)
        return r.returncode
    except (OSError, subprocess.TimeoutExpired) as e:
        log(t("proc.failed", err=str(e)), YEL)
        return -1


def running(names) -> list:
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True,
                             text=True, errors="replace").stdout
    except OSError:
        return []
    want = {n.lower() for n in names}
    found = set()
    for line in out.splitlines():
        img = line.split('","')[0].strip('"').lower()
        if img in want:
            found.add(img)
    return sorted(found)


def kill(names, log):
    for n in running(names):
        run_cmd(["taskkill", "/F", "/T", "/IM", n], log)


def powershell(script: str, env: dict = None, timeout=120) -> subprocess.CompletedProcess:
    """Run PowerShell with UTF-8 output.

    Variable data is passed only through $env:MAPACHE_* variables, never interpolated into `script`.
    """
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='SilentlyContinue'; " + script
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-Command", full], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=e, timeout=timeout)


def ps_json(script: str, env: dict = None, timeout=120) -> list:
    """Run a script that ends in ConvertTo-Json and always return a list."""
    try:
        out = powershell(script, env, timeout).stdout.strip()
        data = json.loads(out) if out else []
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []
    return data if isinstance(data, list) else [data]


def kill_by_path(fragment: str, log):
    """Kill every process whose executable path contains `fragment`."""
    if log.dry or not fragment:
        return
    try:
        powershell("Get-Process | Where-Object { $_.Path -and $_.Path.IndexOf($env:MAPACHE_FRAG, "
                   "[StringComparison]::OrdinalIgnoreCase) -ge 0 } | Stop-Process -Force",
                   env={"MAPACHE_FRAG": str(fragment)}, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pass
    time.sleep(1)


def ensure_closed(names, label: str, log) -> bool:
    """Ask the user to close a program before touching its files. False if skipped."""
    while running(names):
        if log.dry:
            log(t("proc.sim_open", label=label), GRY)
            return True
        r = input(f"      {YEL}{t('proc.is_open', label=label)}{R} {t('proc.open_options')} ").strip().lower()
        if r == "s":
            log(t("proc.skipped_open", label=label), YEL)
            return False
        if r == "c":
            kill(names, log)
            time.sleep(1.5)
    return True
