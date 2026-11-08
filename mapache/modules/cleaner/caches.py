"""Safe cleanup: recycle bin, tool caches, browsers, Steam, temp files and dumps."""
import ctypes
import os
import re
import shutil
import sys
import time
from functools import partial
from pathlib import Path

from ...core.fs import clear_contents, clear_paths, del_paths, disp, exists, in_tool_dir, is_under, lp
from ...core.model import Item
from ...core.paths import DAY, HOME, LOCAL, PD, PF86, ROAMING, SD, TEMP, USERS, WIN
from ...core.proc import ensure_closed, run_cmd
from ...core.winreg_util import reg_get, winreg
from ...i18n import t
from ...ui.console import GRN, GRY, YEL
from .common import cache_item

G = "safe"


# --- Recycle bin ---

def recycle_dirs() -> list:
    out = []
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        try:
            if ctypes.windll.kernel32.GetDriveTypeW(root) != 3:  # fixed drives only
                continue
        except Exception:
            if letter != SD[0]:
                continue
        rb = root + "$Recycle.Bin"
        if os.path.isdir(rb):
            out.append(rb)
    return out


def empty_recycle(admin: bool, log):
    if log.dry:
        log(t("cache.recycle_sim"), GRY)
        return
    try:
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)
    except Exception as e:
        log(str(e), YEL)
    if admin:  # every user's bin
        for rb in recycle_dirs():
            try:
                for sid in os.scandir(rb):
                    if sid.is_dir(follow_symlinks=False):
                        clear_contents(sid.path, log, keep={"desktop.ini"})
            except OSError:
                pass
    log(t("cache.recycle_done"), GRN)


# --- Tool caches ---

def clean_pip(paths, log):
    run_cmd([sys.executable, "-m", "pip", "cache", "purge"], log)
    clear_paths(paths, log)


def clean_npm(paths, log):
    if shutil.which("npm"):
        run_cmd(["cmd", "/c", "npm", "cache", "clean", "--force"], log)
    clear_paths(paths, log)


def clean_closed(exes, label, paths, log):
    if ensure_closed(exes, label, log):
        clear_paths(paths, log)


# --- Browsers ---
BROWSERS = [
    ("Chrome", LOCAL / "Google" / "Chrome" / "User Data", "chrome.exe"),
    ("Edge", LOCAL / "Microsoft" / "Edge" / "User Data", "msedge.exe"),
    ("Brave", LOCAL / "BraveSoftware" / "Brave-Browser" / "User Data", "brave.exe"),
    ("Opera GX", LOCAL / "Opera Software" / "Opera GX Stable", "opera.exe"),
]
PROFILE_CACHES = ["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache",
                  "DawnWebGPUCache", "Service Worker/CacheStorage", "Service Worker/ScriptCache"]
ROOT_CACHES = ["ShaderCache", "GrShaderCache", "GraphiteDawnCache"]


def browser_items(ctx) -> list:
    items = []
    for label, root, exe in BROWSERS:
        if not root.exists():
            continue
        paths = [root / c for c in ROOT_CACHES]
        if label == "Opera GX":
            profiles = [root]
        else:
            try:
                profiles = [p for p in root.iterdir() if p.is_dir() and
                            (p.name in ("Default", "Guest Profile") or p.name.startswith("Profile "))]
            except OSError:
                profiles = []
        for prof in profiles:
            paths += [prof / c for c in PROFILE_CACHES]
        paths = [p for p in paths if exists(p)]
        items += cache_item(ctx, G, t("cache.browser", name=label), paths, "rec", t("cache.browser_note"),
                            action=partial(clean_closed, [exe], label, paths))
    return items


# --- Steam ---

def steam_libs() -> list:
    libs = []
    sp = reg_get(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath") if winreg else None
    root = Path(sp) if sp else PF86 / "Steam"
    if root.exists():
        libs.append(root)
    try:
        txt = (root / "steamapps" / "libraryfolders.vdf").read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r'"path"\s+"([^"]+)"', txt):
            p = Path(m.group(1).replace("\\\\", "\\"))
            if p.exists() and all(os.path.normcase(str(p)) != os.path.normcase(str(x)) for x in libs):
                libs.append(p)
    except OSError:
        pass
    return libs


def steam_items(ctx) -> list:
    libs = steam_libs()
    junk = [lib / "steamapps" / d for lib in libs for d in ("downloading", "temp")]
    shaders = [lib / "steamapps" / "shadercache" for lib in libs]
    return (cache_item(ctx, G, t("cache.steam_junk"), junk, "rec", t("cache.steam_junk_note"),
                       action=partial(clean_closed, ["steam.exe"], "Steam", junk))
            + cache_item(ctx, G, t("cache.steam_shaders"), shaders, "opt", t("cache.steam_shaders_note"),
                         action=partial(clean_closed, ["steam.exe"], "Steam", shaders)))


# --- node_modules ---

def node_modules_items(ctx) -> list:
    if not ctx.scan:
        return []
    stale = []
    for nm in ctx.scan.dirs_named("node_modules"):
        proj = Path(disp(nm)).parent
        # Only user projects. node_modules inside installed programs or editor extensions
        # are part of those programs.
        if not is_under(proj, USERS) or in_tool_dir(proj) or not exists(proj / "package.json"):
            continue
        last = 0.0
        try:
            for e in os.scandir(lp(proj)):
                if e.name.lower() != "node_modules":
                    try:
                        last = max(last, e.stat(follow_symlinks=False).st_mtime)
                    except OSError:
                        pass
        except OSError:
            continue
        if time.time() - last > 90 * DAY:
            stale.append((disp(nm), proj))
    if not stale:
        return []
    names = ", ".join(p.name for _, p in stale[:4]) + ("…" if len(stale) > 4 else "")
    return [Item(G, t("cache.nm", n=len(stale)), ctx.sizes(nm for nm, _ in stale), "rec",
                 t("cache.nm_note", names=names), partial(del_paths, [nm for nm, _ in stale]))]


# --- Detector ---

def detect(ctx) -> list:
    items = []
    items += cache_item(ctx, G, t("cache.recycle"), recycle_dirs(), "rec", t("cache.recycle_note"),
                        action=partial(empty_recycle, ctx.admin), order=99)
    pip = [LOCAL / "pip" / "Cache"]
    items += cache_item(ctx, G, t("cache.pip"), pip, "rec", t("cache.pip_note"), action=partial(clean_pip, pip))
    npm = [LOCAL / "npm-cache", ROAMING / "npm-cache"]
    items += cache_item(ctx, G, t("cache.npm"), npm, "rec", t("cache.npm_note"), action=partial(clean_npm, npm))
    items += cache_item(ctx, G, t("cache.shaders"),
                        [LOCAL / "NVIDIA" / "DXCache", LOCAL / "NVIDIA" / "GLCache", LOCAL / "D3DSCache"],
                        "rec", t("cache.shaders_note"))
    items += cache_item(ctx, G, t("cache.nvidia_installers"), [PD / "NVIDIA Corporation" / "Downloader"],
                        "rec", t("cache.nvidia_installers_note"), admin=True)
    items += cache_item(ctx, G, t("cache.user_temp"), [TEMP], "rec", t("cache.temp_note"))
    items += cache_item(ctx, G, t("cache.win_temp"), [WIN / "Temp"], "rec", t("cache.temp_note"), admin=True)
    items += cache_item(ctx, G, t("cache.app_dumps"), [LOCAL / "CrashDumps"], "rec", t("cache.app_dumps_note"))
    items += cache_item(ctx, G, t("cache.win_dumps"), [WIN / "LiveKernelReports", WIN / "Minidump", WIN / "MEMORY.DMP"],
                        "rec", t("cache.win_dumps_note"), admin=True)
    items += cache_item(ctx, G, t("cache.gradle"), [HOME / ".gradle" / "caches"], "opt", t("cache.gradle_note"))
    items += cache_item(ctx, G, t("cache.nuget"), [HOME / ".nuget" / "packages"], "opt", t("cache.nuget_note"))
    items += cache_item(ctx, G, t("cache.pub"), [LOCAL / "Pub" / "Cache"], "opt", t("cache.pub_note"))
    items += browser_items(ctx)
    items += steam_items(ctx)
    items += node_modules_items(ctx)
    return items
