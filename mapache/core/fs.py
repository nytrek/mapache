"""Filesystem helpers: long paths, sizes and dry-run aware deletion."""
import os
import re
import shutil
import stat
import sys
from pathlib import Path

from ..i18n import t
from ..ui.console import GRN, GRY, YEL
from .paths import FILE_ATTRIBUTE_REPARSE_POINT, HOME, IS_WIN, SKIP_TAGS, USERS


# --- Paths ---

def disp(p) -> str:
    """Path without the \\\\?\\ prefix."""
    s = str(p)
    if s.startswith("\\\\?\\UNC\\"):
        return "\\\\" + s[8:]
    return s[4:] if s.startswith("\\\\?\\") else s


def lp(p) -> str:
    """Path with the \\\\?\\ prefix (long path support)."""
    s = str(p)
    if not IS_WIN or s.startswith("\\\\"):
        return s
    return "\\\\?\\" + os.path.abspath(s)


def norm(p) -> str:
    return os.path.normcase(os.path.normpath(disp(p)))


def ikey(p) -> str:
    """Normalized index key without trailing separator."""
    n = norm(p)
    return n.rstrip("\\/") or n


def is_under(p, parent) -> bool:
    a, b = ikey(p), ikey(parent)
    return a == b or a.startswith(b + os.sep)


# Folders managed by other applications. Loose files inside them are never offered
# (duplicates, node_modules, ...).
TOOL_SEGMENTS = {"appdata", "$recycle.bin", "program files", "program files (x86)", "programdata",
                 "windows", "site-packages", "node_modules", "venv"}


def in_tool_dir(p) -> bool:
    """True if the path goes through a tool or program folder (AppData, Program Files, venvs, dot folders)."""
    segs = [s.lower() for s in re.split(r"[\\/]+", disp(p)) if s]
    return any(s in TOOL_SEGMENTS or (s.startswith(".") and s not in (".", "..")) for s in segs)


# --- Sizes ---

def mtime(p) -> float:
    try:
        return os.stat(lp(p)).st_mtime
    except OSError:
        return 0.0


def _skip_dir(st) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
                and getattr(st, "st_reparse_tag", 0) in SKIP_TAGS)


def dir_size(p) -> int:
    total, stack = 0, [lp(p)]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if not _skip_dir(st):
                            stack.append(e.path)
                    else:
                        total += st.st_size
        except OSError:
            pass
    return total


def stat_size(p) -> int:
    try:
        return os.stat(lp(p)).st_size
    except OSError:
        pass
    try:  # locked files (hiberfil, pagefile) are read from the directory listing
        name = os.path.basename(str(p)).lower()
        with os.scandir(lp(os.path.dirname(str(p)))) as it:
            for e in it:
                if e.name.lower() == name:
                    return e.stat(follow_symlinks=False).st_size
    except OSError:
        pass
    return 0


def path_size(p) -> int:
    s = lp(p)
    if os.path.isdir(s):
        return dir_size(s)
    return stat_size(p) if os.path.lexists(s) else 0


def exists(p) -> bool:
    return bool(p) and os.path.lexists(lp(p))


def user_dirs() -> list:
    out = []
    try:
        for d in USERS.iterdir():
            if d.name.lower() in ("public", "default", "default user", "all users"):
                continue
            try:
                if d.is_dir() and not d.is_symlink() and (d / "NTUSER.DAT").exists():
                    out.append(d)
            except OSError:
                pass
    except OSError:
        pass
    return out or [HOME]


# --- Deletion ---

def _onerr(func, path, *_):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def _rm(p) -> bool:
    s = lp(p)
    try:
        if os.path.isdir(s) and not os.path.islink(s):
            if sys.version_info >= (3, 12):
                shutil.rmtree(s, onexc=_onerr)
            else:
                shutil.rmtree(s, onerror=_onerr)
        elif os.path.lexists(s):
            try:
                os.remove(s)
            except PermissionError:
                os.chmod(s, stat.S_IWRITE)
                os.remove(s)
    except OSError:
        pass
    return not os.path.lexists(s)


def rm(p, log) -> bool:
    if not exists(p):
        return True
    if log.dry:
        log(t("fs.sim_delete", path=disp(p)), GRY)
        return True
    ok = _rm(p)
    log(t("fs.deleted", path=disp(p)) if ok else t("fs.partial", path=disp(p)), GRN if ok else YEL)
    return ok


def clear_contents(p, log, keep=()) -> bool:
    s = lp(p)
    if not os.path.isdir(s):
        return rm(p, log) if os.path.lexists(s) else True
    try:
        entries = [e for e in os.scandir(s) if e.name.lower() not in keep]
    except OSError as e:
        log(t("fs.cant_open", path=disp(p), err=e.strerror), YEL)
        return False
    if log.dry:
        log(t("fs.sim_empty", path=disp(p), n=len(entries)), GRY)
        return True
    fails = sum(0 if _rm(e.path) else 1 for e in entries)
    if fails:
        log(t("fs.in_use_left", path=disp(p), fails=fails, n=len(entries)), YEL)
    else:
        log(t("fs.emptied", path=disp(p)), GRN)
    return fails == 0


def clear_paths(paths, log):
    for p in paths:
        clear_contents(p, log)


def del_paths(paths, log):
    for p in paths:
        rm(p, log)


PROTECTED_NAMES = {"downloads", "documents", "desktop", "videos", "music", "pictures",
                   "onedrive", "virtualbox vms", "users"}


def remove_empty_parent(p, log):
    parent = Path(disp(p)).parent
    if parent.name.lower() in PROTECTED_NAMES or parent.parent == USERS or log.dry:
        return
    try:
        if not any(os.scandir(lp(parent))):
            os.rmdir(lp(parent))
            log(t("fs.empty_dir_removed", path=str(parent)), GRN)
    except OSError:
        pass


def del_files_clean_parent(paths, log):
    for p in paths:
        if rm(p, log):
            remove_empty_parent(p, log)
