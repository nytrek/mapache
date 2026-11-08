"""Large files and folders in each user's Downloads."""
import os
from functools import partial
from pathlib import Path

from ...core.fs import del_paths, disp, lp, mtime, user_dirs
from ...core.model import Item
from ...core.paths import GB
from ...i18n import t
from ...ui.console import ago

ARCHIVES = {".zip", ".7z", ".rar", ".tar", ".gz", ".xz", ".tgz"}
INSTALLERS = {".iso", ".exe", ".msi", ".ova", ".img"} | ARCHIVES


def detect(ctx) -> list:
    items = []
    for udir in user_dirs():
        dl = udir / "Downloads"
        try:
            entries = list(os.scandir(lp(dl)))
        except OSError:
            continue
        for e in entries:
            p = Path(disp(e.path))
            if ctx.claimed_by(p) or ctx.contains_claimed(p):
                continue
            size = ctx.size(p)
            if size < GB:
                continue
            is_dir = e.is_dir(follow_symlinks=False)
            ext = "" if is_dir else p.suffix.lower()
            level = "opt"
            note = t("dl.note_dir" if is_dir else "dl.note_file", user=udir.name, ago=ago(mtime(p)))
            stem = p.name[: -len(ext)] if ext else p.name
            if ext in ARCHIVES and (dl / stem).is_dir():
                level, note = "rec", note + " · " + t("dl.extracted")
            elif ext in INSTALLERS:
                note += " · " + t("dl.installer")
            items.append(Item("dl", p.name, size, level, note, partial(del_paths, [p]), order=40))
    return items
