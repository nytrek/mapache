"""Optimization rules: fixed rules plus dynamic ones for startup entries and third-party tasks."""
import re

from ...core.paths import PD, ROAMING
from ...core.winreg_util import reg_values, winreg
from ..harden.engine import RegValue
from ..harden.rules import Rule
from .actions import BALANCED, POWER_SAVER, PowerPlan, StartupOff, TaskOff, has_battery, schemes, task_list

LEVELS = ["basic", "advanced", "startup", "tasks"]
D = "REG_DWORD"
CV = r"Software\Microsoft\Windows\CurrentVersion"
APPROVED = r"Explorer\StartupApproved"

# Never offered: Windows Security, antivirus software and browser updaters.
PROTECT = re.compile(r"securityhealth|windowsdefender|defender|malwarebytes|kaspersky|eset|avast|avg|bitdefender|"
                     r"norton|sophos|mcafee|trend ?micro|webroot|f-secure", re.I)
BROWSER_UPD = re.compile(r"google ?update|googleupdater|microsoftedgeupdate|edgeupdate|bravesoftware ?update|"
                         r"brave.*update|mozilla|firefox", re.I)
UPDATER = re.compile(r"updat|upgrade", re.I)
# VPN tasks (watchdogs, kill switch, NRPT) are never offered: disabling them can leak traffic.
VPN_TASK = re.compile(r"vpn|wireguard|openvpn|tailscale|warp|zerotier|nrpt|kill ?switch", re.I)


def _hk(name):
    return getattr(winreg, name) if winreg else None


# --- Startup programs ---

def startup_entries() -> list:
    """[(hive, StartupApproved path, value name, detail)] for everything that starts with Windows."""
    if winreg is None:
        return []
    out = []
    v64, v32 = getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)
    for hive, base, view, sub in (("HKCU", CV, 0, "Run"), ("HKLM", CV, v64, "Run"),
                                  ("HKLM", CV, v32, "Run32")):
        for name, cmd in reg_values(_hk("HKEY_CURRENT_USER" if hive == "HKCU" else "HKEY_LOCAL_MACHINE"),
                                    rf"{base}\Run", view).items():
            if name and isinstance(cmd, str):
                out.append((hive, rf"{CV}\{APPROVED}\{sub}", name, cmd))
    for hive, folder in (("HKCU", ROAMING / r"Microsoft\Windows\Start Menu\Programs\Startup"),
                         ("HKLM", PD / r"Microsoft\Windows\Start Menu\Programs\StartUp")):
        try:
            files = [f for f in folder.iterdir() if f.is_file() and f.name.lower() != "desktop.ini"]
        except OSError:
            files = []
        for f in files:
            out.append((hive, rf"{CV}\{APPROVED}\StartupFolder", f.name, str(f)))
    return out


def startup_rules() -> list:
    rules = []
    for hive, path, name, detail in startup_entries():
        if PROTECT.search(name + " " + detail) or BROWSER_UPD.search(name + " " + detail):
            continue
        act = StartupOff(hive, path, name)
        if act.is_applied():  # already disabled entries are not listed
            continue
        rules.append(Rule(f"startup:{hive}:{path.rsplit(chr(92), 1)[-1]}:{name}", "startup", "low",
                          (lambda a=act: [a]), title=name, note=detail))
    return rules


# --- Third-party tasks ---

def task_candidates(tasks: list) -> list:
    """Active third-party tasks that can be offered."""
    out = []
    for d in tasks:
        name, path = str(d.get("Name") or ""), str(d.get("Path") or "\\")
        blob = " ".join(str(d.get(k) or "") for k in ("Name", "Path", "Author", "Exec"))
        if (not name or d.get("State") == "Disabled" or PROTECT.search(blob) or BROWSER_UPD.search(blob)
                or VPN_TASK.search(blob)):
            continue
        out.append((path + name, name, str(d.get("Exec") or "").strip(), bool(UPDATER.search(name + " " + path))))
    return out


SID_RE = re.compile(r"[-_ ]?S-1-5-21-[\d-]+", re.I)


def clean_name(name: str) -> str:
    """Strip the user SID some apps append to task names (display only)."""
    return SID_RE.sub("", name).strip(" -_") or name


def task_rules() -> list:
    rules = []
    for tn, name, exe, updater in task_candidates(task_list()):
        # medium risk marks updaters
        rules.append(Rule(f"task:{tn}", "tasks", "medium" if updater else "low", (lambda tn=tn: [TaskOff(tn)]),
                          title=clean_name(name), note=exe or clean_name(tn)))
    return rules


def dynamic() -> list:
    return startup_rules() + task_rules()


# --- Fixed rules ---

def _desktop_with_saver() -> bool:
    return not has_battery() and BALANCED in schemes()


RULES = [
    Rule("power.not_saver", "basic", "low", lambda: [PowerPlan(BALANCED, avoid=POWER_SAVER)],
         available=_desktop_with_saver, refs=("MS: Power plans",)),
    Rule("game.bg_recording", "basic", "low", lambda: [
        RegValue("HKCU", rf"{CV}\GameDVR", "HistoricalCaptureEnabled", D, 0, default=0)],
        refs=("Settings > Gaming > Captures",)),
    Rule("storage.sense", "advanced", "low", lambda: [
        RegValue("HKCU", rf"{CV}\StorageSense\Parameters\StoragePolicy", "01", D, 1)],
        refs=("Settings > System > Storage > Storage Sense",)),
]

GUIDES = ["dont", "bloat", "drivers", "power"]
