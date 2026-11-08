"""Large programs that may be unused: Unreal Engine, BlueStacks, Android emulators."""
import json
import os
import shutil
import time
from functools import partial
from pathlib import Path

from ...core.fs import del_paths, ikey, lp, rm
from ...core.model import Item
from ...core.paths import DAY, ENV, HOME, LOCAL, PD, PF, PF86
from ...core.proc import ensure_closed, kill_by_path
from ...core.uninstaller import uninstall
from ...core.winreg_util import arp_entries
from ...i18n import t
from ...ui.console import GRN, GRY, YEL, ago

# --- Unreal Engine ---
UE_DAT = PD / "Epic" / "UnrealEngineLauncher" / "LauncherInstalled.dat"
EPIC_MANIFESTS = PD / "Epic" / "EpicGamesLauncher" / "Data" / "Manifests"


def del_unreal(loc: str, log):
    if not ensure_closed(["EpicGamesLauncher.exe", "UnrealEditor.exe"], t("ue.epic_label"), log):
        return
    rm(loc, log)
    if log.dry:
        log(t("ue.sim_registry"), GRY)
        return
    stamp, nloc = time.strftime("%Y%m%d%H%M%S"), ikey(loc)
    try:
        for item in EPIC_MANIFESTS.glob("*.item"):
            try:
                data = json.loads(item.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError):
                continue
            if ikey(data.get("InstallLocation", "")) == nloc:
                shutil.copy2(item, f"{item}.bak{stamp}")
                item.unlink()
                log(t("ue.manifest_removed", name=item.name), GRN)
    except OSError:
        pass
    try:
        data = json.loads(UE_DAT.read_text(encoding="utf-8-sig"))
        lst = data.get("InstallationList", [])
        new = [e for e in lst if ikey(e.get("InstallLocation", "")) != nloc]
        if len(new) != len(lst):
            shutil.copy2(UE_DAT, f"{UE_DAT}.bak{stamp}")
            data["InstallationList"] = new
            UE_DAT.write_text(json.dumps(data, indent="\t"), encoding="utf-8")
            log(t("ue.dat_updated"), GRN)
    except (OSError, ValueError) as e:
        log(t("ue.dat_failed", err=str(e)), YEL)


def detect_unreal(ctx) -> list:
    locs = {}
    try:
        data = json.loads(UE_DAT.read_text(encoding="utf-8-sig"))
        for e in data.get("InstallationList", []):
            if str(e.get("AppName", "")).upper().startswith("UE_") and e.get("InstallLocation"):
                locs[ikey(e["InstallLocation"])] = (e["InstallLocation"], e["AppName"])
    except (OSError, ValueError):
        pass
    for root in (PF / "Epic Games", PF86 / "Epic Games"):
        try:
            for d in root.glob("UE_*"):
                if d.is_dir():
                    locs.setdefault(ikey(d), (str(d), d.name))
        except OSError:
            pass
    items = []
    for loc, name in locs.values():
        if os.path.isdir(lp(loc)):
            items.append(Item("apps", t("ue.title", ver=name[3:].replace("_", ".")), ctx.size(loc), "opt",
                              t("ue.note"), partial(del_unreal, loc), admin=True, order=10))
    return items


# --- BlueStacks ---

def del_bluestacks(inst: str, entry, dirs, log):
    kill_by_path(inst, log)
    if entry:
        uninstall(entry, log)
        kill_by_path(inst, log)
    for d in dirs:
        rm(d, log)


def detect_bluestacks(ctx) -> list:
    try:
        insts = [d for d in PD.glob("BlueStacks_*") if d.is_dir()]
    except OSError:
        insts = []
    if not insts:
        return []
    arp = arp_entries()
    items = []
    for inst in insts:
        tag = inst.name.lower()
        entry = next((e for e in arp if tag in " ".join(str(v) for v in e.values()).lower()), None)
        dirs = [inst] + [p for p in (PF / inst.name, PF86 / inst.name) if p.exists()]
        name = entry["DisplayName"] if entry else "BlueStacks"
        note = t("bs.note", path=str(inst))
        if len(insts) > 1:
            note += " · " + t("bs.note_multi", n=len(insts))
        if not entry:
            note += " · " + t("bs.note_nounins")
        items.append(Item("apps", f"{name} ({inst.name})", ctx.sizes(dirs), "opt", note,
                          partial(del_bluestacks, inst.name, entry, dirs), admin=True, order=10))
    return items


# --- Android emulators ---
EMULATORS = ["emulator.exe", "qemu-system-x86_64.exe", "qemu-system-aarch64.exe",
             "qemu-system-x86_64-headless.exe"]


def del_avd(avd: Path, ini: Path, log):
    if not ensure_closed(EMULATORS, t("avd.emulator_label"), log):
        return
    rm(avd, log)
    rm(ini, log)


def detect_avds(ctx) -> list:
    home = Path(ENV("ANDROID_AVD_HOME") or (Path(ENV("ANDROID_USER_HOME") or HOME / ".android") / "avd"))
    items = []
    try:
        inis = list(home.glob("*.ini"))
    except OSError:
        inis = []
    for ini in inis:
        name = ini.stem
        avd = home / f"{name}.avd"
        try:
            for line in ini.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("path="):
                    cand = Path(line[5:].strip())
                    if cand.exists():
                        avd = cand
        except OSError:
            pass
        if not avd.exists():
            continue
        last = 0.0
        try:
            for e in os.scandir(lp(avd)):
                try:
                    last = max(last, e.stat(follow_symlinks=False).st_mtime)
                except OSError:
                    pass
        except OSError:
            pass
        level = "rec" if time.time() - last > 120 * DAY else "opt"
        items.append(Item("apps", t("avd.title", name=name), ctx.size(avd), level, t("avd.note", ago=ago(last)),
                          partial(del_avd, avd, ini), order=10))
    sdk = Path(ENV("ANDROID_HOME") or ENV("ANDROID_SDK_ROOT") or LOCAL / "Android" / "Sdk")
    imgs = sdk / "system-images"
    if imgs.exists():
        items.append(Item("apps", t("sdk.title"), ctx.size(imgs), "opt", t("sdk.note"),
                          partial(del_paths, [imgs]), order=12))
    return items


def detect(ctx) -> list:
    return detect_unreal(ctx) + detect_bluestacks(ctx) + detect_avds(ctx)
