"""Large byte-identical duplicates in user folders."""
import hashlib
import os
from functools import partial
from pathlib import Path

from ...core.fs import del_files_clean_parent, disp, in_tool_dir, is_under, lp
from ...core.model import Item
from ...core.paths import MB, USERS, VM_EXT
from ...i18n import t

# Identical executables and libraries are often intentional (launchers, portable apps):
# offered as optional, never recommended.
PROGRAM_EXT = {".exe", ".dll", ".sys", ".so", ".jar", ".node", ".pyd"}


def in_skipped_dir(p: str) -> bool:
    """True for tool folders, where duplicates are expected and deleting one breaks the tool."""
    return in_tool_dir(p)


def _phash(p: str, size: int) -> str:
    h = hashlib.blake2b(digest_size=16)
    with open(lp(p), "rb") as f:
        for off in (0, size // 2, max(0, size - MB)):
            f.seek(off)
            h.update(f.read(MB))
    return h.hexdigest()


def _fhash(p: str) -> str:
    h = hashlib.blake2b(digest_size=20)
    with open(lp(p), "rb") as f:
        while True:
            chunk = f.read(8 * MB)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def find_duplicates(files: list) -> list:
    """Group identical files: size, then partial hash, then full hash."""
    by_size = {}
    for b in files:
        by_size.setdefault(b.size, []).append(b)
    groups = []
    for size, g in by_size.items():
        if len(g) < 2:
            continue
        by_p = {}
        for b in g:
            try:
                by_p.setdefault(_phash(b.path, size), []).append(b)
            except OSError:
                pass
        for pg in by_p.values():
            if len(pg) < 2:
                continue
            by_f = {}
            for b in pg:
                try:
                    by_f.setdefault(_fhash(b.path), []).append(b)
                except OSError:
                    pass
            groups += [fg for fg in by_f.values() if len(fg) > 1]
    return groups


def detect(ctx) -> list:
    if not ctx.scan:
        return []
    cands = [b for b in ctx.scan.big
             if is_under(b.path, USERS)
             and os.path.splitext(b.path)[1].lower() not in VM_EXT | {".vbox", ".sav"}
             and not in_skipped_dir(b.path)
             and not ctx.claimed_by(b.path)]
    items = []
    for g in find_duplicates(cands):
        keep = min(g, key=lambda b: (b.ctime, len(b.path)))
        dele = [disp(b.path) for b in g if b is not keep]
        level, note = "rec", t("dup.note", n=len(g), keep=disp(keep.path), dele="; ".join(dele))
        if os.path.splitext(keep.path)[1].lower() in PROGRAM_EXT:
            level, note = "opt", note + " · " + t("dup.program")
        items.append(Item("dup", t("dup.title", name=Path(disp(keep.path)).name), keep.size * len(dele), level,
                          note, partial(del_files_clean_parent, dele), order=30))
        for d in dele:
            ctx.claim(d)
        ctx.claim(keep.path)  # the kept copy must not be offered elsewhere
    return items
