"""Free up space: run detectors, show recommendations, delete the selection."""
import shutil
import time

from ...core.log import Log, new_log_path
from ...core.paths import MB, SYSROOT
from ...i18n import t
from ...ui import selector
from ...ui.console import B, GRN, GRY, R, RED, YEL, CYN, hs, section, size_col, term_width
from . import apps, caches, downloads, dups, system, vms

GROUPS = ["safe", "vm", "dup", "apps", "dl", "sys"]

# order matters: earlier detectors claim paths so later ones skip them
DETECTORS = [
    ("clean.step_vms", vms.detect),
    ("clean.step_dups", dups.detect),
    ("clean.step_apps", apps.detect),
    ("clean.step_caches", caches.detect),
    ("clean.step_downloads", downloads.detect),
    ("clean.step_system", system.detect),
]

CONFIRM_WORDS = {"BORRAR", "DELETE"}


def analyze(ctx) -> list:
    ctx.ensure_scan()
    ctx.claimed = []
    print(f"\n  {B}{t('clean.analyzing')}{R} {GRY}{t('clean.readonly')}{R}")
    items = []
    for key, fn in DETECTORS:
        t0 = time.perf_counter()
        print(f"   · {t(key)}...", end="", flush=True)
        try:
            found = fn(ctx) or []
            items += found
            extra = t("clean.found", n=len(found)) if found else ""
            print(f" {GRY}{extra} {time.perf_counter() - t0:.1f}s{R}")
        except Exception as e:  # a failing detector must not stop the others
            print(f" {YEL}{t('clean.detector_error', err=str(e))}{R}")
    items = [it for it in items if it.size < 0 or it.size >= 50 * MB]
    for it in items:
        it.selected = it.level == "rec" and (ctx.admin or not it.admin)
    items.sort(key=lambda it: (GROUPS.index(it.group), it.level != "rec", -max(it.size, 0)))
    return items


def execute(ctx, sel: list):
    log = Log(new_log_path("clean"), ctx.dry)
    free0 = shutil.disk_usage(SYSROOT).free
    section(t("clean.cleaning"))
    try:
        for n, it in enumerate(sorted(sel, key=lambda x: x.order), 1):
            print(f"\n  {B}[{n}/{len(sel)}] {it.title}{R}")
            log.mark(it.title)
            before = shutil.disk_usage(SYSROOT).free
            try:
                it.action(log)
            except KeyboardInterrupt:
                log(t("clean.interrupted"), YEL)
                break
            except Exception as e:
                log(t("clean.unexpected", err=str(e)), YEL)
            gained = shutil.disk_usage(SYSROOT).free - before
            if gained > MB and not ctx.dry:
                log(t("clean.freed_item", size=hs(gained)), GRN)
    finally:
        log.close()
    ctx.invalidate()
    return shutil.disk_usage(SYSROOT).free - free0, log.path


def run(ctx):
    W = term_width()
    items = analyze(ctx)
    if not items:
        print(f"\n  {GRN}{t('clean.nothing')}{R}")
        return
    print(f"\n  {GRY}{t('clean.hint')}{R}")
    sorts = [(t("sort.recommended"), lambda it: (it.level != "rec", -max(it.size, 0))),
             (t("prog.sort_size"), lambda it: -max(it.size, 0)),
             (t("prog.sort_name"), lambda it: it.title.lower())]
    sel = selector.select(items, ctx.admin, t("clean.title"), group_label=lambda g: t(f"group.{g}"), sorts=sorts)
    if not sel:
        print(f"\n  {GRY}{t('clean.nothing_deleted')}{R}")
        return

    total = sum(max(it.size, 0) for it in sel)
    section(t("clean.will_delete", size=hs(total)), W)
    for it in sel:
        print(f"  {size_col(it.size)}  {it.title}")
    if not ctx.dry:
        print(f"\n  {RED}{B}{t('clean.permanent')}{R}")
        if input(f"  {t('clean.type_confirm', word=B + t('clean.confirm_word') + R)} ").strip().upper() \
                not in CONFIRM_WORDS:
            print(f"  {GRY}{t('clean.cancelled')}{R}")
            return

    freed, log_path = execute(ctx, sel)
    du = shutil.disk_usage(SYSROOT)
    section(t("clean.done"), W)
    if ctx.dry:
        print(f"  {CYN}{t('clean.sim_done', size=hs(total))}{R}")
    else:
        print("  " + t("clean.summary", freed=f"{GRN}{B}{hs(max(freed, 0))}{R}",
                       free=f"{B}{hs(du.free)}{R}", total=hs(du.total)))
    print(f"  {GRY}{t('clean.log_at', path=str(log_path))}{R}")
