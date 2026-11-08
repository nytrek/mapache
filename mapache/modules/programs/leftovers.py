"""Leftovers of a program after uninstalling it (or for a forced removal).

Folders match only on the exact normalized name, never a whole publisher folder or a folder shared
with another installed program. Services, tasks, Run entries, shortcuts and firewall rules match only
if they point into the program folder. AppData/ProgramData items are optional. Registry keys and
tasks are exported before deletion.
"""
import json
import os
import re
from functools import partial
from pathlib import Path

from ...core.backup import reg_delete_key, reg_delete_value, reg_export, task_export
from ...core.fs import disp, exists, ikey, is_under, lp, path_size, rm
from ...core.lnk import lnk_target
from ...core.model import Item
from ...core.paths import GB, HOME, LOCAL, PD, PF, PF86, ROAMING, USERS
from ...core.proc import kill_by_path, powershell, ps_json, run_cmd
from ...core.uninstaller import exe_from
from ...core.winreg_util import key_exists, reg_subkeys, reg_values, winreg
from ...i18n import t
from ...ui.console import GRN, YEL
from .inventory import GENERIC

# --- Names ---
NOISE = {"x64", "x86", "64bit", "32bit", "amd64", "arm64", "win64", "win32", "bit", "user", "setup",
         "inc", "ltd", "llc", "gmbh", "corp", "corporation", "co", "sa", "the", "for", "windows", "version"}
# system keys under Software\, never offered or inspected
SKIP_REG = {"microsoft", "classes", "policies", "wow6432node", "clients", "registeredapplications", "windows"}
# generic words are never a program name
GENERIC_WORDS = {"app", "apps", "application", "applications", "bin", "program", "programs", "data", "files",
                 "current", "common", "shared", "tools", "launcher", "client", "game", "games", "update",
                 "updater", "cache", "temp", "tmp", "local", "roaming", "config", "settings", "user", "users",
                 "default", "packages", "resources", "runtime", "plugins", "logs", "install", "installer"}
# Windows folders inside AppData, ProgramData and Program Files
SYSTEM_DIRS = {"apps", "packages", "microsoft", "temp", "programs", "publishers", "comms", "virtualstore",
               "connecteddevicesplatform", "d3dscache", "crashdumps", "history", "microsoft_corporation",
               "placeholdertilelogofolder", "package cache", "windowsapps", "common files", "windows defender",
               "windows nt", "windowspowershell", "internet explorer", "windows mail", "windows media player",
               "windows photo viewer", "windows sidebar", "modifiablewindowsapps", "reference assemblies",
               "msbuild", "uninstall information", "ssh", "regid.1991-06.com.microsoft", "usoshared",
               "usoprivate", "softwaredistribution", "desktop", "start menu", "templates", "documents"}


def norm(s: str) -> str:
    """'Mozilla Firefox (x64 en-US) 128.0.1' -> 'mozillafirefox'."""
    s = re.sub(r"\(.*?\)|\[.*?\]", " ", (s or "").lower())
    toks = [w for w in re.findall(r"[a-z0-9]+", s) if w not in NOISE and not re.fullmatch(r"v?\d+[a-z]?", w)]
    return "".join(toks)


def pub_norms(publisher: str) -> set:
    toks = [w for w in re.findall(r"[a-z0-9]+", (publisher or "").lower()) if w not in NOISE]
    out = {"".join(toks)} if toks else set()
    if toks and len(toks[0]) >= 4:
        out.add(toks[0])
    return {p for p in out if len(p) >= 3}


def candidates(prog) -> set:
    pubs = pub_norms(prog.publisher)
    own = norm(prog.name)
    names = set()
    for p in pubs:  # "Mozilla Firefox" without the publisher -> "firefox"
        if own.startswith(p) and len(own) > len(p):
            names.add(own[len(p):])
    if prog.location:
        names.add(norm(os.path.basename(prog.location.rstrip("\\/"))))
    # A derived name equal to the publisher is not the program name (the publisher folder may hold
    # other products). The program's own name always counts.
    names = {n for n in names if n not in pubs}
    names.add(own)
    return {n for n in names if len(n) >= 3 and n not in GENERIC_WORDS}


def launcher_locations() -> list:
    """Folders of launcher-managed games (Epic manifests, Steam libraries)."""
    out = []
    try:
        for item in (PD / "Epic" / "EpicGamesLauncher" / "Data" / "Manifests").glob("*.item"):
            try:
                loc = json.loads(item.read_text(encoding="utf-8-sig")).get("InstallLocation")
            except (OSError, ValueError):
                continue
            if loc:
                out.append(loc)
    except OSError:
        pass
    from ..cleaner.caches import steam_libs
    out += [str(lib / "steamapps") for lib in steam_libs()]
    return out


# --- Helpers ---

class Context:
    """What is needed to decide whether something belongs to this program."""

    def __init__(self, prog, others, protected=None):
        self.prog = prog
        self.cands = candidates(prog)
        self.own = norm(prog.name)
        self.pubs = pub_norms(prog.publisher) - {self.own}
        self.loc = prog.location if prog.location and ikey(prog.location) not in GENERIC else ""
        self.other_names = set()
        self.other_locs = list(protected) if protected is not None else launcher_locations()
        for o in others:
            if o.id == prog.id:
                continue
            self.other_names |= candidates(o)
            if o.location:
                self.other_locs.append(o.location)
        # programs installed inside our folder own their subfolders
        self.nested = [o for o in self.other_locs if self.loc and is_under(o, self.loc) and ikey(o) != ikey(self.loc)]
        # if we live inside another program, our folder may contain its data
        self.inside_other = bool(self.loc) and any(is_under(self.loc, o) and ikey(o) != ikey(self.loc)
                                                   for o in self.other_locs)

    def is_mine(self, name: str) -> bool:
        n = norm(name)
        return n in self.cands and n not in self.other_names and n not in self.pubs

    def points_here(self, path: str) -> bool:
        if not (self.loc and path and is_under(path, self.loc)) or any(is_under(path, o) for o in self.nested):
            return False
        # a subfolder named after another installed program is not ours
        rel = disp(path)[len(disp(self.loc).rstrip("\\/")):]
        segs = [norm(s) for s in re.split(r"[\\/]+", rel) if s][:-1]
        return not any(s in self.other_names and s not in self.cands for s in segs)

    def safe_folder(self, folder) -> bool:
        if ikey(folder) in GENERIC or os.path.basename(str(folder).rstrip("\\/")).lower() in SYSTEM_DIRS:
            return False
        return not any(is_under(o, folder) for o in self.other_locs)


def _item(kind, title, size, level, note, action, admin=False, order=50):
    return Item(f"lo_{kind}", title, size, level, note, action, admin=admin, order=order, tag=t(f"lo.kind_{kind}"))


def _clean_path(raw: str) -> str:
    """Normalize service/task paths: quotes, variables, \\??\\ and System32-relative paths."""
    p = exe_from(raw)
    p = re.sub(r"^\\\?\?\\", "", p)
    if re.match(r"(?i)^(\\systemroot|system32)\\", p):
        p = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), p.split("\\", 1)[1] if p.startswith("\\") else p)
    return p


# --- Folders ---

def _del_folder(path, log):
    kill_by_path(str(path), log)
    rm(path, log)


def folders(c: Context, gone: bool) -> list:
    items, seen = [], set()

    own = max(c.prog.size, 0)

    def add(path, level, note):
        k = ikey(path)
        if k in seen or not os.path.isdir(lp(path)) or not c.safe_folder(path):
            return
        seen.add(k)
        size = path_size(path)
        # a leftover folder much larger than the program likely holds other data:
        # never preselected
        if size > max(GB, 2 * own) and ikey(path) != ikey(c.loc or "\0"):
            level, note = "opt", t("lo.note_too_big") + " · " + note
        items.append(_item("folder", disp(path), size, level, note,
                           partial(_del_folder, Path(path)), admin=not is_under(path, USERS), order=60))

    if c.loc:
        if norm(os.path.basename(c.loc.rstrip("\\/"))) in c.pubs:  # may hold other products
            add(c.loc, "opt", t("lo.note_pub_folder"))
        elif c.inside_other:  # shared with the parent program's configuration
            add(c.loc, "opt", t("lo.note_inside_other"))
        else:
            add(c.loc, "rec" if gone else "opt", t("lo.note_location"))
    lowlow = HOME / "AppData" / "LocalLow"
    roots = [(PF, "rec"), (PF86, "rec"), (LOCAL / "Programs", "rec"),
             (PD, "opt"), (LOCAL, "opt"), (ROAMING, "opt"), (lowlow, "opt")]
    for root, level in roots:
        try:
            children = [e for e in os.scandir(lp(root)) if e.is_dir(follow_symlinks=False)]
        except OSError:
            continue
        for e in children:
            name = e.name
            path = Path(root) / name
            note = t("lo.note_program_files") if level == "rec" else t("lo.note_data")
            if c.is_mine(name):
                add(path, level if gone else "opt", note)
            elif norm(name) in c.pubs:  # publisher folder: inspected, never offered whole
                try:
                    for sub in os.scandir(lp(path)):
                        if sub.is_dir(follow_symlinks=False) and c.is_mine(sub.name):
                            add(path / sub.name, level if gone else "opt", note)
                except OSError:
                    pass
    return items


# --- Registry ---

def _views():
    if winreg is None:
        return []
    return [(winreg.HKEY_CURRENT_USER, 0), (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)]


def _hk(hive) -> str:
    return "HKCU" if winreg and hive == winreg.HKEY_CURRENT_USER else "HKLM"


def reg_keys(c: Context, gone: bool) -> list:
    items, seen = [], set()
    for hive, view in _views():
        is_hklm = _hk(hive) == "HKLM"
        for sub in reg_subkeys(hive, "Software", view):
            low = norm(sub)
            if sub.lower() in SKIP_REG:
                continue
            paths = []
            if c.is_mine(sub):
                paths.append(f"Software\\{sub}")
            elif low in c.pubs:
                paths += [f"Software\\{sub}\\{s}" for s in reg_subkeys(hive, f"Software\\{sub}", view) if c.is_mine(s)]
            for p in paths:
                label = f"{_hk(hive)}\\{p}" + (" (32 bits)" if view == getattr(winreg, "KEY_WOW64_32KEY", -1) else "")
                if label.lower() in seen:
                    continue
                seen.add(label.lower())
                items.append(_item("reg", label, 0, "rec" if gone else "opt", t("lo.note_reg"),
                                   partial(reg_delete_key, hive, p, view), admin=is_hklm, order=70))
    return items


def arp_key(prog) -> list:
    e = prog.entry
    if not e or not key_exists(e["_hive"], e["_key"], e["_view"]):
        return []
    label = f"{_hk(e['_hive'])}\\{e['_key']}"
    return [_item("arp", label, 0, "rec", t("lo.note_arp"), partial(reg_delete_key, e["_hive"], e["_key"], e["_view"]),
                  admin=_hk(e["_hive"]) == "HKLM", order=80)]


# --- Services ---
SERVICES = r"SYSTEM\CurrentControlSet\Services"


def _del_service(name, log):
    if winreg is None or not reg_export(winreg.HKEY_LOCAL_MACHINE, f"{SERVICES}\\{name}", 0, log):
        return
    run_cmd(["sc.exe", "stop", name], log)
    run_cmd(["sc.exe", "delete", name], log)


def services(c: Context) -> list:
    if winreg is None or not c.loc:
        return []
    items = []
    hk = winreg.HKEY_LOCAL_MACHINE
    for name in reg_subkeys(hk, SERVICES):
        img = reg_values(hk, f"{SERVICES}\\{name}").get("ImagePath")
        if not img:
            continue
        exe = _clean_path(str(img))
        if c.points_here(exe):
            items.append(_item("service", name, 0, "rec", t("lo.note_service", exe=exe), partial(_del_service, name),
                               admin=True, order=10))
    return items


# --- Scheduled tasks ---
TASKS_PS = ("Get-ScheduledTask | ForEach-Object { $tk = $_; foreach ($a in $tk.Actions) { "
            "[pscustomobject]@{ Path = $tk.TaskPath + $tk.TaskName; Name = $tk.TaskName; Exe = [string]$a.Execute } } }"
            " | ConvertTo-Json -Compress")


def _del_task(task, log):
    if task_export(task, log):
        run_cmd(["schtasks", "/Delete", "/TN", task, "/F"], log)


def tasks(c: Context, all_tasks=None) -> list:
    items, seen = [], set()
    for tk in all_tasks if all_tasks is not None else ps_json(TASKS_PS, timeout=180):
        exe = _clean_path(os.path.expandvars(str(tk.get("Exe") or "")))
        path = str(tk.get("Path") or "")
        dangling = exe and not exists(exe)
        if path in seen or not (c.points_here(exe) or (dangling and any(n in norm(tk.get("Name", "")) for n in c.cands
                                                                            if len(n) >= 5))):
            continue
        seen.add(path)
        items.append(_item("task", path, 0, "rec", t("lo.note_task", exe=exe or "?"), partial(_del_task, path),
                           admin=True, order=20))
    return items


# --- Run entries ---
RUN_KEYS = [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]


def run_entries(c: Context) -> list:
    items = []
    for hive, view in _views():
        for key in RUN_KEYS:
            for name, data in reg_values(hive, key, view).items():
                exe = _clean_path(os.path.expandvars(str(data)))
                if c.points_here(exe) or (exe and not exists(exe) and c.is_mine(name)):
                    items.append(_item("run", f"{_hk(hive)}\\…\\{key.rsplit(chr(92), 1)[-1]}: {name}", 0, "rec",
                                       t("lo.note_run", cmd=str(data)), partial(reg_delete_value, hive, key, name, view),
                                       admin=_hk(hive) == "HKLM", order=30))
    return items


# --- Shortcuts ---

def shortcut_dirs() -> list:
    sm = Path("Microsoft") / "Windows" / "Start Menu" / "Programs"
    return [ROAMING / sm, PD / sm, HOME / "Desktop", USERS / "Public" / "Desktop",
            HOME / "OneDrive" / "Desktop", HOME / "OneDrive" / "Escritorio"]


def shortcuts(c: Context) -> list:
    items = []

    def mine(lnk: Path) -> bool:
        target = lnk_target(lnk)
        if target and c.points_here(target):
            return True
        return c.is_mine(lnk.stem) and (not target or not exists(target))

    for base in shortcut_dirs():
        if not base.exists():
            continue
        try:
            entries = list(os.scandir(lp(base)))
        except OSError:
            continue
        for e in entries:
            p = base / e.name
            if e.is_dir(follow_symlinks=False):
                lnks = list(p.rglob("*.lnk"))
                others = [x for x in p.rglob("*") if x.is_file() and x.suffix.lower() not in (".lnk", ".url", ".ini")]
                if c.is_mine(e.name) and not others and all(mine(x) for x in lnks):
                    items.append(_item("shortcut", disp(p), 0, "rec", t("lo.note_shortcut_dir"), partial(rm, p),
                                       admin=is_under(p, PD) or is_under(p, USERS / "Public"), order=50))
                else:
                    for x in lnks:
                        if mine(x):
                            items.append(_item("shortcut", disp(x), 0, "rec", t("lo.note_shortcut"), partial(rm, x),
                                               admin=is_under(x, PD), order=50))
            elif e.name.lower().endswith(".lnk") and mine(p):
                items.append(_item("shortcut", disp(p), 0, "rec", t("lo.note_shortcut"), partial(rm, p),
                                   admin=is_under(p, PD) or is_under(p, USERS / "Public"), order=50))
    return items


# --- Firewall ---
FW_KEY = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
FW_REMOVE_PS = ("$ids = $env:MAPACHE_IDS | ConvertFrom-Json; foreach ($i in $ids) { "
                "Remove-NetFirewallRule -Name $i; if ($?) { Write-Output \"ok $i\" } }")


def _del_fw(ids, log):
    if winreg is None or not reg_export(winreg.HKEY_LOCAL_MACHINE, FW_KEY, 0, log):
        return
    if log.dry:
        for i in ids:
            log(t("lo.sim_fw", rule=i))
        return
    # rule ids go through an environment variable, never into the script
    r = powershell(FW_REMOVE_PS, env={"MAPACHE_IDS": json.dumps(ids)})
    done = r.stdout.count("ok ")
    log(t("lo.fw_removed", n=done, m=len(ids)), GRN if done == len(ids) else YEL)


def firewall(c: Context) -> list:
    if winreg is None or not c.loc:
        return []
    ids, apps = [], set()
    for rid, data in reg_values(winreg.HKEY_LOCAL_MACHINE, FW_KEY).items():
        m = re.search(r"\|App=([^|]+)", str(data))
        if m:
            app = os.path.expandvars(m.group(1))
            if c.points_here(app):
                ids.append(rid)
                apps.add(os.path.basename(app))
    if not ids:
        return []
    return [_item("firewall", t("lo.fw_title", n=len(ids)), 0, "rec", t("lo.note_fw", apps=", ".join(sorted(apps))),
                  partial(_del_fw, ids), admin=True, order=40)]


# --- Entry point ---

def scan(prog, others, gone: bool, all_tasks=None) -> list:
    """All leftovers of `prog`. `gone` = the uninstaller finished and the program is unregistered."""
    if prog.kind == "store":
        data = LOCAL / "Packages" / prog.store.get("PackageFamilyName", "")
        if prog.store.get("PackageFamilyName") and data.exists():
            return [_item("folder", disp(data), path_size(data), "rec" if gone else "opt", t("lo.note_store_data"),
                          partial(rm, data), order=60)]
        return []
    c = Context(prog, others)
    return (services(c) + tasks(c, all_tasks) + run_entries(c) + firewall(c) + shortcuts(c)
            + folders(c, gone) + reg_keys(c, gone) + arp_key(prog))
