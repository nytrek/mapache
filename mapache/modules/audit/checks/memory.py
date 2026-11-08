"""Memory artifacts on disk: hiberfil.sys, pagefile.sys and memory dumps.

Severity depends on BitLocker: without it, anyone with physical access can read them.
"""
import os

from ....core.fs import lp, stat_size
from ....core.paths import LOCAL, MB, SD, WIN
from ....i18n import t
from . import R, check
from .crypto import bitlocker_state

POWER = r"SYSTEM\CurrentControlSet\Control\Power"
MM = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
CRASH = r"SYSTEM\CurrentControlSet\Control\CrashControl"


def _bl(f):
    st = bitlocker_state(f)
    return True if st == "on" else False if st in ("off", "suspended", "decrypting") else None


def _amplify(f, base_weight, status_if_off="fail"):
    """(weight, status without BitLocker, detail suffix)."""
    bl = _bl(f)
    if bl is True:
        return base_weight, None, " · " + t("audit.mem.encrypted")
    if bl is False:
        return base_weight + 2, status_if_off, " · " + t("audit.mem.no_bitlocker")
    return base_weight, None, ""


@check("hiber", "memory", 1, refs=("ATT&CK T1003",), harden="mem.hiber")
def hiber(f):
    size = getattr(f, "hiber_size", None)
    if size is None:
        size = stat_size(SD + "\\hiberfil.sys")
    enabled = f.val(POWER, "HibernateEnabled")
    if not size and enabled != 1:
        return R("pass", t("audit.off"))
    w, off_status, suffix = _amplify(f, 1)
    reduced = f.val(POWER, "HiberFileType") == 2
    detail = t("audit.hiber.on", size=f"{size / (1024 ** 3):.1f} GB", kind=t(
        "audit.hiber.reduced" if reduced else "audit.hiber.full")) + suffix
    if _bl(f):
        return R("pass", detail, weight=w)
    return R(off_status or "warn", detail, weight=w)


@check("pagefile_clear", "memory", 1, refs=("MS: Clear virtual memory pagefile",), harden="mem.clear_pagefile")
def pagefile_clear(f):
    if f.val(MM, "ClearPageFileAtShutdown") == 1:
        return R("pass", t("audit.on"))
    w, off_status, suffix = _amplify(f, 1, "warn")
    if _bl(f):
        return R("pass", t("audit.pagefile.not_cleared") + suffix, weight=w)
    return R(off_status or "warn", t("audit.pagefile.not_cleared") + suffix, weight=w)


DUMP_TYPES = {0: "none", 1: "complete", 2: "kernel", 3: "small", 7: "automatic"}


@check("crashdump", "memory", 1, refs=("MS: Memory dump file options",), harden="mem.small_dumps")
def crashdump(f):
    v = f.val(CRASH, "CrashDumpEnabled")
    kind = DUMP_TYPES.get(v, "automatic" if v is None else str(v))
    detail = t(f"audit.crashdump.{kind}") if kind in DUMP_TYPES.values() else str(v)
    if kind in ("none", "small"):
        return R("pass", detail)
    w, off_status, suffix = _amplify(f, 2 if kind == "complete" else 1, "warn")
    if _bl(f):
        return R("pass", detail + suffix, weight=w)
    return R("fail" if kind == "complete" and off_status else "warn", detail + suffix, weight=w)


def find_dumps():
    """[(path, size)] of memory dumps, or None if unreadable."""
    out, denied = [], False
    for d, recursive in ((WIN / "Minidump", False), (WIN / "LiveKernelReports", True), (LOCAL / "CrashDumps", False)):
        stack = [str(d)]
        while stack:
            cur = stack.pop()
            try:
                with os.scandir(lp(cur)) as it:
                    for e in it:
                        if e.is_dir(follow_symlinks=False):
                            if recursive:
                                stack.append(os.path.join(cur, e.name))
                        elif e.name.lower().endswith(".dmp"):
                            out.append((os.path.join(cur, e.name), e.stat(follow_symlinks=False).st_size))
            except FileNotFoundError:
                pass
            except OSError:
                denied = True
    full = stat_size(WIN / "MEMORY.DMP")
    if full:
        out.append((str(WIN / "MEMORY.DMP"), full))
    return None if denied and not out else out


@check("dumps_present", "memory", 1, refs=("ATT&CK T1003",))
def dumps_present(f):
    dumps = getattr(f, "dumps", None)
    if dumps is None:
        dumps = find_dumps()
    if dumps is None:
        return R("unknown", t("audit.need_admin"), admin=True)
    total = sum(s for _, s in dumps)
    if total < 50 * MB:
        return R("pass", t("audit.dumps.none") if not dumps else t("audit.dumps.small", n=len(dumps)))
    w, off_status, suffix = _amplify(f, 1, "fail")
    items = [f"{s / MB:,.0f} MB  {p}" for p, s in sorted(dumps, key=lambda x: -x[1])[:10]]
    detail = t("audit.dumps.found", n=len(dumps), size=f"{total / (1024 ** 3):.1f} GB") + suffix
    return R(off_status or "warn", detail, items=items, weight=w)
