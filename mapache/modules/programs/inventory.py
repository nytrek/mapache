"""Program inventory: the three uninstall registry branches and Store apps."""
import ctypes
import datetime as dt
import html
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ...core.fs import dir_size, ikey, is_under, lp
from ...core.paths import HOME, LOCAL, PD, PF, PF86, ROAMING, SYSROOT, USERS, WIN
from ...core.proc import ps_json
from ...core.uninstaller import exe_from, plan
from ...core.winreg_util import arp_entries, key_mtime, reg_values, winreg


@dataclass
class Program:
    id: str
    name: str
    kind: str  # "win32" | "store"
    version: str = ""
    publisher: str = ""
    installed: float = 0.0  # install date (timestamp)
    location: str = ""
    size: int = -1
    size_src: str = ""  # "scan" (measured) | "est" (EstimatedSize) | ""
    method: str = ""  # uninstaller type (see core.uninstaller.plan) or "store"
    critical: str = ""  # "", "runtime", "driver", "security", "anticheat", "system"
    user_scope: bool = False  # registered under HKCU
    entry: dict = field(default_factory=dict, repr=False)
    store: dict = field(default_factory=dict, repr=False)
    provisioned: bool = False
    aumid_prefix: str = ""  # "family!" prefix used to match Store apps in UserAssist
    last_used: float = 0.0
    runs: int = 0
    lu_src: str = ""


# --- Filters ---

def is_system_entry(v: dict) -> bool:
    """Components, patches and updates that are not user-facing programs."""
    if v.get("SystemComponent") == "1":
        return True
    if v.get("ParentKeyName") or v.get("ParentDisplayName"):
        return True
    if (v.get("ReleaseType") or "").lower() in ("update", "hotfix", "security update", "service pack"):
        return True
    return bool(re.search(r"\bKB\d{6,8}\b", v.get("DisplayName", "")))


CRITICAL = [
    ("runtime", r"visual c\+\+.*(redistributable|runtime)|\bvcredist|\.net (framework|runtime|desktop runtime)|"
                r"windows desktop runtime|asp\.net core|\bdirectx\b|webview2|windows (sdk|software development kit)|"
                r"microsoft visual studio installer|windowsappruntime|microsoft\.vclibs|microsoft\.ui\.xaml|"
                r"microsoft\.net\.|java\(tm\)|java \d+ update|\bopenjdk\b"),
    ("driver", r"\bdriver\b|controlador|chipset|nvidia (graphics|physx|hd audio|usbc|frameview)|physx|realtek|"
               r"intel\(r\)|amd (software|chipset|ryzen)|synaptics|\belan\b|bluetooth|wi-?fi"),
    ("security", r"defender|antivirus|anti-virus|malwarebytes|\beset\b|kaspersky|bitdefender|norton|avast|"
                 r"\bavg\b|mcafee|sophos|sentinel|crowdstrike|sechealthui"),
    ("anticheat", r"easy ?anti-?cheat|battl?eye|vanguard|faceit|ricochet|javelin|nprotect|xigncode"),
    ("system", r"^microsoft edge|update health tools|pc health check|gameinput|microsoft\.windowsstore|"
               r"desktopappinstaller|storepurchaseapp|microsoft\.services\.store|winget|gamingservices|"
               r"languageexperiencepack|winappruntime|applicationcompatibilityenhancements|"
               r"windows subsystem for linux"),
]


def critical_kind(name: str, publisher: str = "") -> str:
    s = f"{name} {publisher}".lower()
    for kind, rx in CRITICAL:
        if re.search(rx, s):
            return kind
    return ""


# --- Location ---

def _generic() -> set:
    """Folders that are never a program's own folder."""
    roots = [SYSROOT, PF, PF86, PF / "Common Files", PF86 / "Common Files", PD, WIN, USERS, HOME, LOCAL,
             ROAMING, LOCAL / "Programs", HOME / "AppData", HOME / "AppData" / "LocalLow", HOME / "Desktop",
             HOME / "Downloads", HOME / "Documents", PF / "WindowsApps"]
    return {ikey(p) for p in roots}


GENERIC = _generic()
# Generic subfolders: the program folder is the parent (CapCut\Apps -> CapCut,
# Chrome\Application -> Chrome)
NOT_APP_DIRS = {"uninstall", "uninst", "_uninst", "uninstaller", "bin", "x64", "x86", "app", "apps",
                "application", "current", "64bit", "32bit", "win64", "win32"}


def app_root(d: str) -> str:
    """Walk up while the folder name is generic."""
    while d and os.path.basename(d.rstrip("\\/")).lower() in NOT_APP_DIRS:
        parent = os.path.dirname(d.rstrip("\\/"))
        if not valid_location(parent):
            break
        d = parent
    return d


def valid_location(d: str) -> bool:
    if not d:
        return False
    k = ikey(d)
    if k in GENERIC or len(k) <= 3:
        return False
    for bad in (WIN, PD / "Package Cache", PD / "Microsoft", LOCAL / "Temp", LOCAL / "Package Cache"):
        if is_under(d, bad):
            return False
    return os.path.isdir(lp(d))


def steam_location(sub: str) -> str:
    """Steam games uninstall through steam.exe, so their folder comes from appmanifest_<id>.acf."""
    m = re.fullmatch(r"Steam App (\d+)", sub or "")
    if not m:
        return ""
    from ..cleaner.caches import steam_libs
    for lib in steam_libs():
        try:
            acf = (lib / "steamapps" / f"appmanifest_{m.group(1)}.acf").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        d = re.search(r'"installdir"\s+"([^"]+)"', acf)
        if d:
            return str(lib / "steamapps" / "common" / d.group(1))
    return ""


def python_location(name: str) -> str:
    """Python install path from Software\\Python\\PythonCore (PEP 514)."""
    m = re.match(r"Python (\d+\.\d+)\.\d+.*?(\(32-bit\))?", name or "")
    if not m or winreg is None:
        return ""
    ver = m.group(1) + ("-32" if m.group(2) else "")
    for hive, view in ((winreg.HKEY_CURRENT_USER, 0), (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
                       (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)):
        p = reg_values(hive, rf"Software\Python\PythonCore\{ver}\InstallPath", view).get("")
        if p:
            return str(p).rstrip("\\/")
    return ""


def infer_location(v: dict) -> str:
    loc = os.path.expandvars((v.get("InstallLocation") or "").strip().strip('"')).rstrip("\\/")
    if valid_location(loc):
        return app_root(loc)
    for special in (steam_location(v.get("_sub", "")), python_location(v.get("DisplayName", ""))):
        if valid_location(special):
            return special
    if re.search(r"steam://|com\.epicgames\.launcher://", v.get("UninstallString", ""), re.I):
        return ""  # the executable belongs to the launcher, not the game
    for fld in ("DisplayIcon", "UninstallString", "QuietUninstallString"):
        exe = exe_from(v.get(fld, ""))
        if not exe or "msiexec" in exe.lower():
            continue
        d = os.path.dirname(exe)
        if valid_location(d):
            return app_root(d)
    return ""


def measure(ctx, path: str) -> int:
    """Size from the shared scan, walking the folder if not indexed. -1 = no access."""
    if ctx.scan is not None:
        s = ctx.scan.size(path)
        if s is not None:
            return s
    try:
        with os.scandir(lp(path)):
            pass
    except OSError:
        return -1
    return dir_size(path)


def parse_date(s: str) -> float:
    try:
        return dt.datetime.strptime((s or "").strip()[:8], "%Y%m%d").timestamp()
    except ValueError:
        return 0.0


# --- Win32 ---

def win32_programs(ctx) -> list:
    seen = {}
    for v in arp_entries():
        if is_system_entry(v):
            continue
        name = v["DisplayName"].strip()
        key = (name.lower(), v.get("DisplayVersion", ""))
        prev = seen.get(key)
        if prev and (prev.get("UninstallString") or not v.get("UninstallString")):
            continue  # same app in two branches: keep the one with an uninstaller
        seen[key] = v
    progs = []
    for v in seen.values():
        loc = infer_location(v)
        size, src = (measure(ctx, loc), "scan") if loc else (-1, "")
        if size < 0:
            try:
                size, src = int(v.get("EstimatedSize") or 0) * 1024 or -1, "est"
            except ValueError:
                size, src = -1, ""
        if size < 0:
            src = ""
        method, _ = plan(v)
        user = winreg is not None and v["_hive"] == winreg.HKEY_CURRENT_USER
        progs.append(Program(
            id=f"{'HKCU' if user else 'HKLM'}{v['_view']}:{v['_sub']}", name=v["DisplayName"].strip(),
            kind="win32", version=v.get("DisplayVersion", ""), publisher=v.get("Publisher", "").strip(),
            installed=parse_date(v.get("InstallDate")) or key_mtime(v["_hive"], v["_key"], v["_view"]),
            location=loc, size=size, size_src=src, method=method,
            critical=critical_kind(v["DisplayName"], v.get("Publisher", "")), user_scope=user, entry=v))
    return progs


# --- Microsoft Store ---

STORE_PS = (
    "Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.IsResourcePackage -and "
    "-not $_.NonRemovable -and [string]$_.SignatureKind -ne 'System' } | Select-Object Name, "
    "PackageFullName, PackageFamilyName, InstallLocation, Publisher, Version, "
    "@{n='Sig';e={[string]$_.SignatureKind}} | ConvertTo-Json -Compress -Depth 2")
PROV_PS = "Get-AppxProvisionedPackage -Online | Select-Object DisplayName | ConvertTo-Json -Compress"


def load_indirect(src: str) -> str:
    """Resolve "@{Package?ms-resource://...}" with SHLoadIndirectString."""
    try:
        buf = ctypes.create_unicode_buffer(512)
        if ctypes.windll.shlwapi.SHLoadIndirectString(src, buf, 512, None) == 0:
            return buf.value
    except (AttributeError, OSError):
        pass
    return ""


def store_display_name(pkg: dict) -> str:
    name, full = pkg.get("Name", ""), pkg.get("PackageFullName", "")
    try:
        text = (Path(pkg.get("InstallLocation") or "") / "AppxManifest.xml").read_text(encoding="utf-8",
                                                                                       errors="replace")
        m = re.search(r"<Properties>.*?<DisplayName>(.*?)</DisplayName>", text, re.S)
        dn = html.unescape(m.group(1).strip()) if m else ""
    except OSError:
        dn = ""
    if dn.startswith("ms-resource:"):
        res = dn[len("ms-resource:"):]
        if res.startswith("//"):
            uris = ["ms-resource:" + res]
        elif res.startswith("/"):
            uris = [f"ms-resource://{name}{res}"]
        else:
            uris = [f"ms-resource://{name}/Resources/{res}", f"ms-resource://{name}/{res}"]
        dn = next((s for s in (load_indirect(f"@{{{full}?{u}}}") for u in uris) if s), "")
    return dn or re.sub(r"^(Microsoft|MicrosoftWindows|MicrosoftCorporationII)\.", "", name)


def store_programs(ctx) -> list:
    prov = set()
    if ctx.admin:
        prov = {str(p.get("DisplayName", "")).lower() for p in ps_json(PROV_PS)}
    progs = []
    for pkg in ps_json(STORE_PS):
        fam, loc = pkg.get("PackageFamilyName", ""), pkg.get("InstallLocation") or ""
        data = LOCAL / "Packages" / fam
        try:
            installed = os.stat(lp(data)).st_ctime
        except OSError:
            installed = 0.0
        pub = re.search(r"CN=([^,]+)", pkg.get("Publisher", "") or "")
        name = store_display_name(pkg)
        size = measure(ctx, loc) if loc else -1
        progs.append(Program(
            id=f"appx:{pkg.get('PackageFullName', '')}", name=name, kind="store",
            version=str(pkg.get("Version", "")), publisher=pub.group(1).strip('"') if pub else "",
            installed=installed, location=loc, size=size, size_src="scan" if size >= 0 else "",
            method="store", critical=critical_kind(pkg.get("Name", "") + " " + name), user_scope=True,
            store=pkg, provisioned=pkg.get("Name", "").lower() in prov, aumid_prefix=fam.lower() + "!"))
    return progs


def collect(ctx) -> list:
    return win32_programs(ctx) + store_programs(ctx)
