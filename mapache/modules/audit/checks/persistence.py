"""Persistence and infostealer indicators: autoruns, tasks, services, WMI, IFEO, hosts, proxy, certificates."""
import ipaddress
import os
import re
import time
from pathlib import Path

from ....core.fs import disp, exists, is_under, lp
from ....core.lnk import lnk_target
from ....core.paths import DAY, LOCAL, PD, ROAMING, SD, TEMP, USERS, WIN
from ....core.uninstaller import split_cmd
from ....i18n import t
from ..facts import as_list, expand
from . import R, check

RUN_KEYS = [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", 0),
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 0),
            ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", 0),
            ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", 0),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", 0),
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", 0)]
STARTUP_DIRS = [ROAMING / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
                PD / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"]

LOLBIN = re.compile(
    r"(powershell|pwsh)(\.exe)?\b.*(\s-e(nc|ncodedcommand)?\s|\s-w(indowstyle)?\s+hid|iex\b|invoke-expression|"
    r"downloadstring|downloadfile|frombase64string|invoke-webrequest|\biwr\b|net\.webclient)"
    r"|\bmshta(\.exe)?\b|\b(wscript|cscript)(\.exe)?\b.*\.(vbs|vbe|js|jse|wsf)"
    r"|\brundll32(\.exe)?\b.*\\(users|programdata|temp|appdata)\\|\brundll32(\.exe)?\b.*javascript:"
    r"|\bregsvr32(\.exe)?\b.*(/i:|scrobj|https?:)|\bcertutil(\.exe)?\b.*(urlcache|-decode)"
    r"|\bbitsadmin(\.exe)?\b.*/transfer|cmd(\.exe)?\s+/c\s+.*(curl|powershell|certutil)", re.I)
STD_ROOT = {"windows", "program files", "program files (x86)", "programdata", "users", "$recycle.bin",
            "system volume information", "recovery", "perflogs", "$winreagent", "boot", "documents and settings"}
PE_EXT = {".exe", ".dll", ".scr", ".com", ".cpl", ".sys"}
SCRIPT_EXT = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".bat", ".cmd"}


def user_writable(path: str) -> bool:
    """Folders writable by a non-admin user."""
    if not path:
        return False
    if is_under(path, USERS) or is_under(path, WIN / "Temp") or is_under(path, TEMP):
        return True
    if is_under(path, PD) and not is_under(path, PD / "Microsoft") and not is_under(path, PD / "Package Cache"):
        return True
    p = disp(path)
    drive, rest = os.path.splitdrive(p)
    if drive.upper() == SD.upper():
        first = rest.strip("\\/").split("\\")[0].lower()
        return bool(first) and first not in STD_ROOT and "\\" in rest.strip("\\/")
    return False


def resolve_exe(cmd: str) -> str:
    """Executable of a command line."""
    # expand variables only; stripping quotes here would break '"C:\x\a.exe" -arg'
    exe, _ = split_cmd(os.path.expandvars((cmd or "").strip()))
    exe = exe.strip('"')
    if exe and not os.path.dirname(exe):
        for d in (WIN / "System32", WIN):
            cand = d / (exe if exe.lower().endswith(".exe") else exe + ".exe")
            if exists(cand):
                return str(cand)
    return exe


def classify(f, cmd: str):
    """('suspicious'|'missing'|'ok', reason, exe)."""
    exe = resolve_exe(cmd)
    if LOLBIN.search(cmd or ""):
        return "suspicious", t("audit.persist.lolbin"), exe
    if exe and os.path.isabs(exe) and not exists(exe):
        return "missing", t("audit.persist.missing"), exe
    if user_writable(exe):
        sig = f.signature(exe)
        if sig is None or sig[0] != "Valid":
            return "suspicious", t("audit.persist.unsigned_user_dir", sig=(sig or ("?",))[0] or "?"), exe
    return "ok", "", exe


def _evaluate(f, entries, weight_fail=None):
    """entries: [(label, command)] -> R."""
    f.check_signatures([resolve_exe(c) for _, c in entries if user_writable(resolve_exe(c))])
    sus, miss, ok = [], [], []
    for label, cmd in entries:
        kind, why, _ = classify(f, cmd)
        line = f"{label}: {cmd}"
        if kind == "suspicious":
            sus.append(f"⚠ {why} · {line}")
        elif kind == "missing":
            miss.append(f"{why} · {line}")
        else:
            ok.append(line)
    if sus:
        return R("fail", t("audit.persist.suspicious", n=len(sus), m=len(entries)), items=sus + miss + ok)
    if miss:
        return R("warn", t("audit.persist.missing_n", n=len(miss), m=len(entries)), items=miss + ok)
    return R("pass", t("audit.persist.ok", n=len(entries)), items=ok)


# --- Autoruns ---

def startup_entries(f) -> list:
    entries = []
    for hive, key, view in RUN_KEYS:
        for name, data in f.values(key, hive=hive, view=view).items():
            if name and data:
                entries.append((f"{hive}\\…\\{key.rsplit(chr(92), 1)[-1]} '{name}'", str(data)))
    files = getattr(f, "startup_files", None)
    if files is None:
        files = []
        for d in STARTUP_DIRS:
            try:
                files += [str(Path(d) / e.name) for e in os.scandir(lp(d)) if e.name.lower() != "desktop.ini"]
            except OSError:
                pass
    for p in files:
        target = lnk_target(p) if p.lower().endswith(".lnk") else p
        entries.append((f"Startup '{os.path.basename(p)}'", target or p))
    return entries


@check("run_entries", "persistence", 4, refs=("ATT&CK T1547.001",))
def run_entries(f):
    entries = startup_entries(f)
    if not entries:
        return R("pass", t("audit.persist.ok", n=0))
    return _evaluate(f, entries)


# --- Scheduled tasks ---

@check("tasks", "persistence", 3, refs=("ATT&CK T1053.005",))
def tasks(f):
    data = f.psv("tasks")
    if data is None:
        return R("unknown", t("audit.cant_read"))
    entries = []
    for tk in as_list(data):
        path, args = str(tk.get("Path", "")), str(tk.get("Args") or "")
        exe = str(tk.get("Exe") or "").strip().strip('"')  # some task paths are already quoted
        if not exe:
            continue
        cmd = f'"{exe}" {args}'.strip()
        # Microsoft tasks only matter if they point to a writable folder or use a LOLBin
        if path.lower().startswith("\\microsoft\\") and not (user_writable(resolve_exe(cmd)) or LOLBIN.search(cmd)):
            continue
        entries.append((path, cmd))
    return _evaluate(f, entries)


# --- Services ---
SVC = r"SYSTEM\CurrentControlSet\Services"


def _services(f):
    for name in f.subkeys(SVC):
        v = f.values(rf"{SVC}\{name}")
        img, typ, start = v.get("ImagePath"), v.get("Type"), v.get("Start")
        if not img or not isinstance(typ, int) or not typ & 0x30 or start == 4:
            continue  # Win32 services only, not disabled
        yield name, str(img)


@check("services", "persistence", 3, refs=("ATT&CK T1543.003",))
def services(f):
    entries = [(f"service '{n}'", img) for n, img in _services(f) if user_writable(resolve_exe(img))
               or LOLBIN.search(img)]
    if not entries:
        return R("pass", t("audit.services.ok"))
    return _evaluate(f, entries)


def is_unquoted(img: str) -> bool:
    s = (img or "").strip()
    if not s or s.startswith('"'):
        return False
    low = s.lower()
    if low.startswith(("\\systemroot", "system32", "%systemroot%", "\\??\\", "%windir%")):
        return False
    m = re.match(r"(.+?\.exe)", s, re.I)
    return bool(m and " " in m.group(1))


@check("unquoted", "persistence", 2, refs=("ATT&CK T1574.009",))
def unquoted(f):
    bad = [f"{n}: {img}" for n, img in _services(f) if is_unquoted(img)]
    if bad:
        return R("warn", t("audit.unquoted.found", n=len(bad)), items=bad)
    return R("pass", t("audit.unquoted.none"))


# --- WMI, IFEO, AppInit, Winlogon ---

@check("wmi", "persistence", 4, refs=("ATT&CK T1546.003",))
def wmi(f):
    data = f.psv("wmi")
    if data is None:
        return R("unknown", t("audit.need_admin"), admin=True)
    bad = []
    for c in as_list(data):
        cls = str(c.get("Class", ""))
        if cls in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
            what = c.get("CommandLineTemplate") or c.get("ScriptFileName") or (c.get("ScriptText") or "")[:120]
            bad.append(f"{c.get('Name')} ({cls}): {what}")
    if bad:
        return R("fail", t("audit.wmi.found", n=len(bad)), items=bad)
    return R("pass", t("audit.wmi.none"))


IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
SPE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"


# Debugger=taskkill/systray is how debloat tools block telemetry binaries; not malware
BLOCKER = re.compile(r"(^|\\)(taskkill|systray)(\.exe)?(\s|$)", re.I)


@check("ifeo", "persistence", 4, refs=("ATT&CK T1546.012",))
def ifeo(f):
    bad, blocks = [], []
    for exe in f.subkeys(IFEO):
        dbg = f.val(rf"{IFEO}\{exe}", "Debugger")
        if dbg:
            (blocks if BLOCKER.search(expand(str(dbg))) else bad).append(f"{exe} → Debugger: {dbg}")
    for exe in f.subkeys(SPE):
        mon = f.val(rf"{SPE}\{exe}", "MonitorProcess")
        if mon:
            bad.append(f"{exe} → SilentProcessExit: {mon}")
    if bad:
        return R("fail", t("audit.ifeo.found", n=len(bad)), items=bad + blocks)
    if blocks:
        return R("pass", t("audit.ifeo.blocks", n=len(blocks)), items=blocks)
    return R("pass", t("audit.ifeo.none"))


@check("appinit", "persistence", 4, refs=("ATT&CK T1546.010",))
def appinit(f):
    bad, dormant = [], []
    for key in (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"):
        v = f.values(key)
        dlls = str(v.get("AppInit_DLLs") or "").strip()
        if dlls:
            (bad if v.get("LoadAppInit_DLLs") == 1 else dormant).append(f"{key}: {dlls}")
    if bad:
        return R("fail", t("audit.appinit.on"), items=bad + dormant)
    if dormant:
        return R("warn", t("audit.appinit.dormant"), items=dormant)
    return R("pass", t("audit.appinit.none"))


WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


@check("winlogon", "persistence", 4, refs=("ATT&CK T1547.004",))
def winlogon(f):
    bad = []
    shell = str(f.val(WINLOGON, "Shell", default="explorer.exe")).strip()
    if shell.lower() != "explorer.exe":
        bad.append(f"Shell = {shell}")
    ui = str(f.val(WINLOGON, "Userinit", default="")).strip().rstrip(",").strip()
    if ui and expand(ui).lower() not in (str(WIN / "system32" / "userinit.exe").lower(), "userinit.exe"):
        bad.append(f"Userinit = {ui}")
    user_shell = f.val(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", hive="HKCU")
    if user_shell:
        bad.append(f"HKCU Shell = {user_shell}")
    if bad:
        return R("fail", t("audit.winlogon.modified"), items=bad)
    return R("pass", t("audit.winlogon.ok"))


# --- hosts, proxy, certificates ---
SECURITY_DOMAINS = re.compile(
    r"(windowsupdate\.|update\.microsoft\.com|wdcp\.microsoft|definitionupdates|smartscreen|"
    r"wd\.microsoft|defender|malwarebytes|kaspersky|eset\.|avast|avg\.com|bitdefender|norton|mcafee|"
    r"sophos|virustotal|avira|trendmicro|emsisoft|hitmanpro)", re.I)


def parse_hosts(text: str) -> list:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2:
            out += [(parts[0], h) for h in parts[1:]]
    return out


@check("hosts", "persistence", 3, refs=("ATT&CK T1565.001",))
def hosts(f):
    entries = parse_hosts(f.read_text(WIN / "System32" / "drivers" / "etc" / "hosts"))
    blocked_sec, redirects, blocks = [], [], []
    for ip, host in entries:
        if host.lower() in ("localhost", "localhost.localdomain"):
            continue
        try:
            addr = ipaddress.ip_address(ip)
            sink = addr.is_loopback or addr.is_unspecified
        except ValueError:
            sink = False
        if SECURITY_DOMAINS.search(host):
            blocked_sec.append(f"{ip} {host}")
        elif sink:
            blocks.append(f"{ip} {host}")
        else:
            redirects.append(f"{ip} {host}")
    if blocked_sec:
        return R("fail", t("audit.hosts.security", n=len(blocked_sec)), items=blocked_sec + redirects)
    if redirects:
        return R("warn", t("audit.hosts.redirects", n=len(redirects)), items=redirects)
    if blocks:
        return R("pass", t("audit.hosts.blocks", n=len(blocks)), items=blocks[:5])
    return R("pass", t("audit.hosts.clean"))


@check("proxy", "persistence", 2, refs=("ATT&CK T1090",))
def proxy(f):
    v = f.values(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", hive="HKCU")
    items = []
    if v.get("ProxyEnable") == 1 and v.get("ProxyServer"):
        items.append(f"ProxyServer = {v['ProxyServer']}")
    if v.get("AutoConfigURL"):
        items.append(f"AutoConfigURL = {v['AutoConfigURL']}")
    if items:
        return R("warn", t("audit.proxy.on"), items=items)
    return R("pass", t("audit.off"))


@check("rootcerts", "persistence", 3, refs=("ATT&CK T1553.004",))
def rootcerts(f):
    data = f.psv("rootcerts")
    if data is None:
        return R("unknown", t("audit.cant_read"))
    certs = [c for c in as_list(data) if isinstance(c, dict) and c.get("Thumbprint")]
    if not certs:
        return R("pass", t("audit.rootcerts.none"))
    items = [f"{c.get('Subject')} · {c.get('NotAfter')} · {c.get('Thumbprint')}" for c in certs]
    return R("warn", t("audit.rootcerts.found", n=len(certs)), items=items)


# --- Recent executables ---
SKIP_RECENT = ("\\npm\\", "\\microsoft\\", "\\packages\\", "\\programs\\", "\\nvidia", "\\steam\\")


def recent_files(days: int = 14) -> list:
    """Executables and scripts recently modified in common dropper locations."""
    limit = time.time() - days * DAY
    roots = [(TEMP, 2, True), (ROAMING, 1, False), (LOCAL, 0, False), (USERS / "Public", 2, True), (PD, 0, False)]
    out = []
    for root, depth, scripts_too in roots:
        stack = [(str(root), 0)]
        while stack:
            cur, lvl = stack.pop()
            if any(s in cur.lower() + "\\" for s in SKIP_RECENT) and lvl > 0:
                continue
            try:
                with os.scandir(lp(cur)) as it:
                    for e in it:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                if lvl < depth:
                                    stack.append((os.path.join(cur, e.name), lvl + 1))
                                continue
                            ext = os.path.splitext(e.name)[1].lower()
                            if ext in PE_EXT or (scripts_too and ext in SCRIPT_EXT):
                                if e.stat(follow_symlinks=False).st_mtime >= limit:
                                    out.append(os.path.join(cur, e.name))
                        except OSError:
                            continue
            except OSError:
                continue
            if len(out) > 500:
                return out
    return out


@check("recent_exes", "persistence", 2, refs=("ATT&CK T1204.002",))
def recent_exes(f):
    files = getattr(f, "recent", None)
    if files is None:
        files = recent_files()
    pes = [p for p in files if os.path.splitext(p)[1].lower() in PE_EXT]
    f.check_signatures(pes)
    unsigned = []
    for p in pes:
        sig = f.signature(p)
        if sig is None or sig[0] != "Valid":
            unsigned.append(f"{(sig or ('?',))[0] or '?'} · {p}")
    scripts = [f"script · {p}" for p in files if os.path.splitext(p)[1].lower() in SCRIPT_EXT]
    if unsigned or scripts:
        return R("warn", t("audit.recent.found", n=len(unsigned) + len(scripts)), items=(unsigned + scripts)[:25])
    return R("pass", t("audit.recent.none", n=len(files)))
