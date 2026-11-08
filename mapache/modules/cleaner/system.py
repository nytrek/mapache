"""Windows cleanup: Update cache, Windows.old, hibernation and DISM."""
import os
from functools import partial

from ...core.fs import clear_contents, rm, stat_size
from ...core.model import Item
from ...core.paths import SD, WIN
from ...core.proc import run_cmd
from ...i18n import t
from .common import cache_item

G = "sys"


def clean_wu(log):
    run_cmd(["net", "stop", "wuauserv"], log)
    run_cmd(["net", "stop", "bits"], log)
    clear_contents(WIN / "SoftwareDistribution" / "Download", log)
    run_cmd(["net", "start", "wuauserv"], log)
    run_cmd(["net", "start", "bits"], log)


def del_windows_old(p: str, log):
    # takeown expects /D Y on English Windows and /D S on Spanish
    if run_cmd(["takeown", "/F", p, "/R", "/A", "/D", "Y"], log, timeout=3600) != 0:
        run_cmd(["takeown", "/F", p, "/R", "/A", "/D", "S"], log, timeout=3600)
    run_cmd(["icacls", p, "/grant", "*S-1-5-32-544:F", "/T", "/C", "/Q"], log, timeout=3600)
    rm(p, log)


def run_dism(log):
    run_cmd(["DISM", "/Online", "/Cleanup-Image", "/StartComponentCleanup"], log, live=True)


def detect(ctx) -> list:
    items = []
    items += cache_item(ctx, G, t("sys.wu"), [WIN / "SoftwareDistribution" / "Download"], "rec", t("sys.wu_note"),
                        action=clean_wu, admin=True, order=60)
    wold = SD + "\\Windows.old"
    if os.path.isdir(wold):
        items.append(Item(G, t("sys.wold"), ctx.size(wold), "rec", t("sys.wold_note"),
                          partial(del_windows_old, wold), admin=True, order=60))
    hib = stat_size(SD + "\\hiberfil.sys")
    if hib:
        items.append(Item(G, t("sys.hib"), hib, "opt", t("sys.hib_note"),
                          partial(run_cmd, ["powercfg", "/h", "off"]), admin=True, order=60))
    items.append(Item(G, t("sys.dism"), -1, "opt", t("sys.dism_note"), run_dism, admin=True, order=90))
    return items
