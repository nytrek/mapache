"""Programs: list installed software with real size and last use, uninstall it and clean leftovers."""
import time

from ...core.log import Log, new_log_path
from ...core.model import Item
from ...core.proc import powershell, ps_json
from ...core.uninstaller import is_user_entry, plan, shown, uninstall
from ...i18n import t
from ...ui import selector
from ...ui.console import B, CYN, GRN, GRY, R, RED, YEL, ago, is_yes, section, size_col, term_width
from . import inventory, lastuse, leftovers

CONFIRM_UNINSTALL = {"DESINSTALAR", "UNINSTALL"}
CONFIRM_DELETE = {"BORRAR", "DELETE"}
GROUPS = ["win32", "store", "critical"]
LO_GROUPS = ["lo_service", "lo_task", "lo_run", "lo_firewall", "lo_shortcut", "lo_folder", "lo_reg", "lo_arp"]


def _date(ts) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else "?"


def describe(p, admin: bool) -> str:
    parts = [x for x in (p.publisher, f"v{p.version}" if p.version else "") if x]
    parts.append(t("prog.installed", date=_date(p.installed)))
    if p.last_used:
        parts.append(t("prog.lu_detail", ago=ago(p.last_used), src=t(f"prog.src_{p.lu_src}"),
                       runs=p.runs or "?"))
    if p.size_src == "est":
        parts.append(t("prog.size_est"))
    parts.append(t(f"unins.m_{p.method}"))
    if p.provisioned:
        parts.append(t("prog.provisioned"))
    if p.critical:
        parts.append(t(f"prog.crit_{p.critical}"))
    if admin and p.kind == "win32" and p.user_scope:
        parts.append(t("prog.hkcu_note"))
    parts.append(p.location or t("prog.no_location"))
    return " · ".join(parts)


def to_item(p, admin: bool) -> Item:
    tag = t("prog.used", ago=ago(p.last_used)) if p.last_used else t("prog.lu_none")
    return Item("critical" if p.critical else p.kind, p.name, p.size, "opt", describe(p, admin), None,
                admin=p.kind == "win32" and not p.user_scope, tag=tag, key=p)


SORTS = [
    ("prog.sort_size", lambda it: -max(it.size, 0)),
    ("prog.sort_lastuse", lambda it: (it.key.last_used, -max(it.size, 0))),
    ("prog.sort_installed", lambda it: -it.key.installed),
    ("prog.sort_name", lambda it: it.title.lower()),
]


def explain_sources(status: dict):
    ua, pf = status["userassist"], status["prefetch"]
    print(f"  {GRY}{t('prog.lu_intro')}{R}")
    if ua != "ok":
        print(f"  {YEL}· {t(f'prog.ua_{ua}')}{R}")
    if pf != "ok":
        print(f"  {YEL}· {t(f'prog.pf_{pf}')}{R}")


# --- Uninstall ---

def remove_store(p, log) -> bool:
    full = p.store.get("PackageFullName", "")
    log(t("unins.running", name=p.name, method=t("unins.m_store")))
    if log.dry:
        log(t("proc.sim_run", cmd=f"Remove-AppxPackage -Package {full}"), GRY)
        return True
    r = powershell("Remove-AppxPackage -Package $env:MAPACHE_PKG; if ($?) { 'MAPACHE_OK' }",
                   env={"MAPACHE_PKG": full}, timeout=900)
    if "MAPACHE_OK" in r.stdout:
        log(t("unins.done", name=p.name), GRN)
        return True
    for line in r.stderr.strip().splitlines()[-3:]:
        log(f"  {line}", GRY)
    log(t("unins.still_there", name=p.name), YEL)
    return False


def clean_leftovers(ctx, p, progs, gone, forced, log, cache):
    print(f"\n  {B}{t('prog.scanning_leftovers')}{R}")
    if "tasks" not in cache:
        cache["tasks"] = ps_json(leftovers.TASKS_PS, timeout=180)
    items = leftovers.scan(p, progs, gone or forced, cache["tasks"])
    if not items:
        print(f"  {GRN}{t('prog.no_leftovers')}{R}")
        return
    for it in items:
        it.selected = it.level == "rec" and (ctx.admin or not it.admin)
    items.sort(key=lambda it: (LO_GROUPS.index(it.group), it.title.lower()))
    title = t("prog.leftovers_title", name=p.name)
    sel = selector.select(items, ctx.admin, title, group_label=lambda g: t(f"group.{g}"))
    if not sel:
        print(f"  {GRY}{t('clean.nothing_deleted')}{R}")
        return
    if not ctx.dry:
        print(f"\n  {RED}{B}{t('prog.leftovers_permanent')}{R}")
        if input(f"  {t('clean.type_confirm', word=B + t('clean.confirm_word') + R)} ").strip().upper() \
                not in CONFIRM_DELETE:
            print(f"  {GRY}{t('clean.cancelled')}{R}")
            return
    for it in sorted(sel, key=lambda x: x.order):
        print(f"\n  {B}· {it.title}{R}")
        log.mark(it.title)
        try:
            it.action(log)
        except Exception as e:  # a failing leftover must not stop the others
            log(t("clean.unexpected", err=str(e)), YEL)


def process(ctx, p, progs, log, cache):
    method = p.method
    forced = False
    if p.kind == "store":
        gone = remove_store(p, log)
    elif method in ("none", "missing"):
        log(t("prog.broken", name=p.name), YEL)
        forced = True
        gone = False
    else:
        gone = uninstall(p.entry, log, ctx.admin)
        if not gone and not ctx.dry:
            print(f"\n  {YEL}{t('prog.still_installed')}{R}")
            if not is_yes(input(f"  {t('prog.ask_force')} "), default=False):
                return
            forced = True
    clean_leftovers(ctx, p, progs, gone, forced, log, cache)


# --- Main flow ---

def run(ctx):
    W = term_width()
    ctx.ensure_scan()
    print(f"\n  {B}{t('prog.loading')}{R} {GRY}{t('clean.readonly')}{R}")
    t0 = time.perf_counter()
    progs = inventory.collect(ctx)
    status = lastuse.assign(progs, ctx.admin)
    print(f"  {GRY}{t('prog.found', n=len(progs), s=f'{time.perf_counter() - t0:.1f}')}{R}")
    explain_sources(status)
    if not progs:
        return
    items = [to_item(p, ctx.admin) for p in progs]
    sorts = [(t(k), fn) for k, fn in SORTS]
    print(f"\n  {GRY}{t('prog.hint')}{R}")
    sel = selector.select(items, ctx.admin, t("prog.title"), group_label=lambda g: t(f"group.prog_{g}"),
                          sorts=sorts)
    if not sel:
        print(f"\n  {GRY}{t('prog.nothing')}{R}")
        return

    chosen = [it.key for it in sel]
    section(t("prog.will_uninstall", n=len(chosen)), W)
    for p in chosen:
        print(f"  {size_col(p.size)}  {B}{p.name}{R}  {GRY}{t(f'unins.m_{p.method}')}{R}")
        if p.kind == "win32":
            _, cmd = plan(p.entry)
            if cmd:
                print(f"             {GRY}$ {shown(cmd)}{R}")
            if ctx.admin and is_user_entry(p.entry):
                print(f"             {YEL}{t('prog.hkcu_note')}{R}")
        if p.critical:
            print(f"             {RED}{t(f'prog.crit_{p.critical}')}{R}")
    if any(p.critical for p in chosen):
        print(f"\n  {RED}{B}{t('prog.critical_warn')}{R}")
    if not ctx.dry:
        print(f"\n  {YEL}{t('prog.close_programs')}{R}")
        if input(f"  {t('clean.type_confirm', word=B + t('prog.confirm_word') + R)} ").strip().upper() \
                not in CONFIRM_UNINSTALL:
            print(f"  {GRY}{t('clean.cancelled')}{R}")
            return

    log = Log(new_log_path("programs"), ctx.dry)
    cache = {}
    try:
        for n, p in enumerate(chosen, 1):
            section(f"[{n}/{len(chosen)}] {p.name}", W)
            log.mark(p.name)
            try:
                process(ctx, p, progs, log, cache)
            except KeyboardInterrupt:
                log(t("clean.interrupted"), YEL)
                break
    finally:
        log.close()
    ctx.invalidate()
    section(t("clean.done"), W)
    if ctx.dry:
        print(f"  {CYN}{t('prog.sim_done')}{R}")
    print(f"  {GRY}{t('clean.log_at', path=str(log.path))}{R}")
    print(f"  {GRY}{t('prog.backups_at')}{R}")

