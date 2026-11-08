"""Official uninstallers: detect the installer type and run it silently when possible.

The executable path is always quoted (unquoted paths with spaces are a privilege escalation vector).
HKCU entries are user-writable, so running them elevated asks for separate confirmation.
"""
import os
import re
import shutil
import subprocess
import time

from ..i18n import t
from ..ui.console import CYN, GRN, GRY, R, YEL, is_yes
from .fs import lp
from .proc import run_cmd
from .winreg_util import key_exists, winreg

GUID = r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
OK_CODES = {0, 3010, 1605, 1641}  # 3010/1641 = reboot required, 1605 = not installed


def split_cmd(cmd: str):
    """Split "exe args" even when the path has spaces and no quotes."""
    s = (cmd or "").strip()
    if not s:
        return "", ""
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 0:
            return s[1:end], s[end + 1:].strip()
        return s.strip('"'), ""
    m = re.match(r"(.+?\.exe)(?=\s|$)(.*)", s, re.I)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    exe, _, args = s.partition(" ")
    return exe, args.strip()


def exe_from(value: str) -> str:
    """Executable path from an UninstallString or DisplayIcon value."""
    exe, _ = split_cmd(re.sub(r",\s*-?\d+\s*$", "", (value or "").strip()))
    return os.path.expandvars(exe.strip('"'))


def sniff(exe: str) -> str:
    """Installer type, detected from signatures inside the executable."""
    try:
        with open(lp(exe), "rb") as f:
            head = f.read(4 * 1024 * 1024)
            try:
                f.seek(-1024 * 1024, os.SEEK_END)
                head += f.read()
            except OSError:
                pass
    except OSError:
        return ""
    if b"Inno Setup" in head or b"I\0n\0n\0o\0 \0S\0e\0t\0u\0p" in head:
        return "inno"
    if b"Nullsoft" in head or b"NullsoftInst" in head:
        return "nsis"
    return ""


def plan(entry: dict):
    """Return (method, command). Methods: msi, quiet, inno, nsis, interactive, missing, none."""
    quiet = (entry.get("QuietUninstallString") or "").strip()
    cmd = (entry.get("UninstallString") or "").strip()
    m = re.search(r"msiexec(?:\.exe)?\"?\s.*?(" + GUID + ")", cmd, re.I)
    if m or (entry.get("WindowsInstaller") == "1" and re.fullmatch(GUID, entry.get("_sub", ""))):
        guid = m.group(1) if m else entry["_sub"]
        return "msi", ["msiexec.exe", "/x", guid, "/qn", "/norestart"]
    base = quiet or cmd
    if not base:
        return "none", ""
    w = re.match(r"winget(?:\.exe)?\s+uninstall\s+--product-code\s+\"?([\w.\-]+)\"?", base, re.I)
    if w:  # winget portable packages
        if not shutil.which("winget"):
            return "missing", base
        return "winget", ["winget", "uninstall", "--product-code", w.group(1), "--silent",
                          "--disable-interactivity", "--accept-source-agreements"]
    exe, args = split_cmd(base)
    exe = os.path.expandvars(exe)
    if not os.path.isfile(lp(exe)):
        return "missing", base
    quoted = f'"{exe}"' + (f" {args}" if args else "")
    if quiet:
        return "quiet", quoted
    kind = sniff(exe)
    if kind == "inno":
        return "inno", quoted + " /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
    if kind == "nsis":
        return "nsis", quoted + " /S"
    return "interactive", quoted


def shown(cmd) -> str:
    return cmd if isinstance(cmd, str) else subprocess.list2cmdline(cmd)


def _wait_gone(entry, log, timeout=600) -> bool:
    """Inno and NSIS relaunch from %TEMP%; the reliable end signal is the registry entry going away."""
    hive, key, view = entry.get("_hive"), entry.get("_key"), entry.get("_view", 0)
    if hive is None or not key:
        return False
    t0 = time.time()
    print(f"      {GRY}{t('unins.waiting')}{R}", end="", flush=True)
    try:
        while time.time() - t0 < timeout:
            if not key_exists(hive, key, view):
                print()
                return True
            time.sleep(1)
            print(".", end="", flush=True)
    except KeyboardInterrupt:
        pass
    print()
    return not key_exists(hive, key, view)


def interactive_cmd(entry, method, cmd):
    """Interactive version of the uninstaller, used if the silent one fails."""
    if method == "msi":
        return cmd[:3]
    if method == "winget":
        return cmd[:4]
    exe, args = split_cmd(entry.get("UninstallString", ""))
    exe = os.path.expandvars(exe)
    if not exe or not os.path.isfile(lp(exe)):
        return None
    return f'"{exe}"' + (f" {args}" if args else "")


def is_user_entry(entry) -> bool:
    return winreg is not None and entry.get("_hive") == winreg.HKEY_CURRENT_USER


def uninstall(entry: dict, log, admin: bool = False) -> bool:
    """Run the official uninstaller. True if the program is no longer registered (or in dry run)."""
    name = entry.get("DisplayName", "?")
    method, cmd = plan(entry)
    if method in ("none", "missing"):
        log(t("unins.none" if method == "none" else "unins.missing", name=name), YEL)
        return False
    if admin and is_user_entry(entry) and not log.dry:
        log(t("unins.hkcu_warn"), YEL)
        log(f"  {shown(cmd)}", GRY)
        if not is_yes(input(f"      {t('unins.hkcu_confirm')} "), default=False):
            log(t("unins.skipped", name=name), YEL)
            return False
    silent = method != "interactive"
    log(t("unins.running", name=name, method=t(f"unins.m_{method}")))
    rc = run_cmd(cmd, log, live=not silent, timeout=3600)
    if log.dry:
        return True
    if not silent:
        input(f"      {CYN}{t('unins.press_enter')}{R}")
        gone = not key_exists(entry["_hive"], entry["_key"], entry.get("_view", 0))
    else:
        gone = rc in OK_CODES and _wait_gone(entry, log)
    if not gone and silent and rc not in OK_CODES:
        log(t("unins.silent_failed", rc=rc), YEL)
        icmd = interactive_cmd(entry, method, cmd)
        if icmd and is_yes(input(f"      {t('unins.retry_interactive')} ")):
            run_cmd(icmd, log, live=True, timeout=3600)
            input(f"      {CYN}{t('unins.press_enter')}{R}")
            gone = not key_exists(entry["_hive"], entry["_key"], entry.get("_view", 0))
            rc = 0
    if rc in (3010, 1641):
        log(t("unins.reboot"), YEL)
    if gone:
        log(t("unins.done", name=name), GRN)
    else:
        log(t("unins.still_there", name=name), YEL)
    return gone
