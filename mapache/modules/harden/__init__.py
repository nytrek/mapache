"""Reversible hardening by level.

Before any change: a restore point, a JSON snapshot with each previous value and a reg export of every
touched key. The snapshot is written after each change, so a partial run can still be undone.
"""
import json
import time

from ...core.backup import BACKUP_DIR, reg_export
from ...core.log import Log, new_log_path
from ...core.model import Item
from ...core.proc import powershell
from ...core.winreg_util import key_exists, winreg
from ...i18n import has, t
from ...ui import selector
from ...ui.console import B, CYN, GRN, GRY, R, RED, YEL, is_yes, section, term_width
from .engine import RegValue, from_dict
from .rules import AUDIT_ALIASES, BY_ID, GUIDES, LEVELS, RULES

CONFIRM = {"APLICAR", "APPLY"}
RISK_COL = {"low": GRN, "medium": YEL, "high": RED}


class Suite:
    """A set of rules sharing the apply/undo/guides flow.

    `key` prefixes its texts (<key>.<id>.title) and snapshots (<key>_<date>.json).
    Missing generic texts fall back to harden.*.
    """

    def __init__(self, key, rules, guides, levels=None, dynamic=None):
        self.key, self.rules, self.guides = key, rules, guides
        self.levels = levels or LEVELS
        self.dynamic = dynamic  # () -> [Rule] built from the current machine
        self.by_id = {r.id: r for r in rules}

    def all_rules(self) -> list:
        extra = list(self.dynamic()) if self.dynamic else []
        self.by_id.update({r.id: r for r in extra})
        return list(self.rules) + extra

    def tx(self, name, **kw) -> str:
        k = f"{self.key}.{name}"
        return t(k, **kw) if has(k) else t(f"harden.{name}", **kw)

    def title(self, rule_id) -> str:
        r = self.by_id.get(rule_id)
        return r.title if r is not None and r.title else t(f"{self.key}.{rule_id}.title")

    def breaks(self, rule) -> str:
        if rule.title:  # dynamic rule: group text, or a risk-specific one if present
            k = f"{self.key}.{rule.level}.breaks"
            return t(f"{k}_{rule.risk}") if has(f"{k}_{rule.risk}") else t(k)
        return t(f"{self.key}.{rule.id}.breaks")


HARDEN = Suite("harden", RULES, GUIDES)


# --- State ---

def evaluate(rules=None) -> list:
    """[(rule, actions, states, applied)] for rules available on this machine."""
    out = []
    for rule in rules or RULES:
        if not rule.is_available():
            continue
        try:
            actions = rule.build()
            states = [a.read() for a in actions]
        except Exception:  # unreadable rules are not offered
            continue
        if not actions:
            continue
        done = all(a.is_applied(s) for a, s in zip(actions, states))
        out.append((rule, actions, states, done))
    return out


def rule_note(rule, suite=HARDEN) -> str:
    desc = rule.note if rule.title else t(f"{suite.key}.{rule.id}.desc")
    parts = [desc, t("harden.may_break", what=suite.breaks(rule))]
    if rule.reboot:
        parts.append(t("harden.needs_reboot"))
    return " · ".join(parts)


def expand_ids(ids) -> set:
    out = set()
    for i in ids or ():
        out |= set(AUDIT_ALIASES.get(i, [i]))
    return out


# --- Restore point ---

def restore_point(log, desc="Mapache hardening") -> bool:
    """True if it is OK to continue. Windows allows one restore point per 24 h by default."""
    if log.dry:
        log(t("harden.sim_restore"), GRY)
        return True
    print(f"  {GRY}{t('harden.creating_restore')}{R}")
    r = powershell("try { Checkpoint-Computer -Description $env:MAPACHE_DESC -RestorePointType MODIFY_SETTINGS "
                   "-ErrorAction Stop -WarningVariable w 3>$null; if ($w) { 'WARN ' + ($w -join ' ') } else { 'OK' } }"
                   " catch { 'ERR ' + $_.Exception.Message }", env={"MAPACHE_DESC": desc}, timeout=900)
    out = (r.stdout or "").strip()
    if out.startswith("OK"):
        log(t("harden.restore_ok"), GRN)
        return True
    if out.startswith("WARN"):
        log(t("harden.restore_recent"), YEL)
        return True
    log(t("harden.restore_failed", err=out[4:].strip()[:200] or "?"), YEL)
    print(f"  {YEL}{t('harden.restore_how')}{R}")
    return is_yes(input(f"  {t('harden.continue_without_restore')} "), default=False)


# --- Apply ---

def snapshot_path(suite=HARDEN):
    return BACKUP_DIR / f"{suite.key}_{time.strftime('%Y%m%d_%H%M%S')}.json"


def save_snapshot(path, snap):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")


def apply_rules(ctx, chosen, log, suite=HARDEN) -> dict:
    """chosen: [(rule, actions)]. Return the snapshot with each change and its previous state."""
    snap = {"date": time.strftime("%Y-%m-%d %H:%M:%S"), "suite": suite.key, "reverted": False, "changes": []}
    path = snapshot_path(suite)
    exported = set()
    for rule, actions in chosen:
        print(f"\n  {B}· {suite.title(rule.id)}{R}")
        log.mark(rule.id)
        for a in actions:
            before = a.read()
            if a.is_applied(before):
                continue
            if isinstance(a, RegValue) and (a.hive, a.path, a.view) not in exported and winreg is not None:
                hive = winreg.HKEY_LOCAL_MACHINE if a.hive == "HKLM" else winreg.HKEY_CURRENT_USER
                # Missing keys have nothing to back up; the snapshot records exists=False
                if key_exists(hive, a.path, a.view):
                    reg_export(hive, a.path, a.view, log)
                exported.add((a.hive, a.path, a.view))
            ok = a.apply(log)
            snap["changes"].append({"rule": rule.id, "title": suite.title(rule.id), "action": a.to_dict(),
                                    "before": before, "ok": ok})
            if not ctx.dry:
                save_snapshot(path, snap)  # saved after every change
            log(t("harden.applied", what=a.describe()) if ok else t("harden.apply_failed", what=a.describe()),
                GRN if ok else YEL)
    snap["path"] = str(path) if not ctx.dry else ""
    return snap


def run_apply(ctx, preselect=None, suite=HARDEN):
    W = term_width()
    print(f"\n  {B}{t('harden.reading')}{R} {GRY}{t('audit.readonly')}{R}")
    state = evaluate(suite.all_rules())
    pending = [(r, a) for r, a, s, done in state if not done]
    done_n = sum(1 for *_, done in state if done)
    print(f"  {GRY}{t('harden.status', done=done_n, pending=len(pending))}{R}")
    if not pending:
        print(f"\n  {GRN}{suite.tx('all_done')}{R}")
        return
    want = expand_ids(preselect)
    items = []
    for rule, actions in pending:
        it = Item(rule.level, suite.title(rule.id), 0, "rec" if rule.level == "basic" else "opt",
                  rule_note(rule, suite), None, admin=True, tag=t(f"harden.risk_{rule.risk}"), key=(rule, actions))
        # only basic rules are preselected
        it.selected = rule.level == "basic" and (preselect is None or rule.id in want)
        items.append(it)
    items.sort(key=lambda it: (suite.levels.index(it.group), it.title.lower()))
    print(f"\n  {GRY}{suite.tx('hint')}{R}")
    # dry run allows selecting everything without admin
    sel = selector.select(items, ctx.admin or ctx.dry, suite.tx("title"), group_label=lambda g: suite.tx(f"level_{g}"))
    if not sel:
        print(f"\n  {GRY}{t('harden.nothing')}{R}")
        return

    chosen = [it.key for it in sel]
    section(t("harden.will_apply", n=len(chosen)), W)
    for rule, actions in chosen:
        col = RISK_COL[rule.risk]
        print(f"  {col}{t(f'harden.risk_{rule.risk}'):<12}{R} {B}{suite.title(rule.id)}{R}")
        for a in actions[:4]:
            print(f"               {GRY}{a.describe()}{R}")
        if len(actions) > 4:
            print(f"               {GRY}{t('harden.more', n=len(actions) - 4)}{R}")
        if rule.risk != "low":
            print(f"               {YEL}{t('harden.may_break', what=suite.breaks(rule))}{R}")
    if not ctx.dry:
        if not ctx.admin:
            print(f"\n  {YEL}{t('harden.need_admin')}{R}")
            return
        print(f"\n  {CYN}{t('harden.reversible')}{R}")
        if input(f"  {t('clean.type_confirm', word=B + t('harden.confirm_word') + R)} ").strip().upper() not in CONFIRM:
            print(f"  {GRY}{t('clean.cancelled')}{R}")
            return

    log = Log(new_log_path(suite.key), ctx.dry)
    try:
        section(t("harden.applying"), W)
        if not restore_point(log, f"Mapache {suite.key}"):
            print(f"  {GRY}{t('clean.cancelled')}{R}")
            return
        snap = apply_rules(ctx, chosen, log, suite)
    finally:
        log.close()
    ok = sum(1 for c in snap["changes"] if c["ok"])
    bad = len(snap["changes"]) - ok
    section(t("clean.done"), W)
    if ctx.dry:
        print(f"  {CYN}{t('harden.sim_done', n=len(snap['changes']))}{R}")
    else:
        print(f"  {GRN}{t('harden.done', ok=ok)}{R}" + (f"  {YEL}{t('harden.failed_n', n=bad)}{R}" if bad else ""))
        print(f"  {GRY}{suite.tx('snapshot_at', path=snap['path'])}{R}")
    if any(r.reboot for r, _ in chosen):
        print(f"  {YEL}{t('harden.reboot_needed')}{R}")
    print(f"  {GRY}{t('clean.log_at', path=str(log.path))}{R}")


# --- Undo ---

def list_snapshots(suite=HARDEN) -> list:
    out = []
    for p in sorted(BACKUP_DIR.glob(f"{suite.key}_*.json"), reverse=True):
        try:
            snap = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not snap.get("reverted") and any(c.get("ok") and not c.get("reverted") for c in snap.get("changes", [])):
            out.append((p, snap))
    return out


def revert_snapshot(path, snap, log) -> tuple:
    ok = bad = 0
    for c in reversed(snap.get("changes", [])):
        if not c.get("ok") or c.get("reverted"):
            continue
        a = from_dict(c["action"])
        if a.revert(c.get("before") or {}, log):
            ok += 1
            log(t("harden.reverted", what=a.describe()), GRN)
            if not log.dry:
                c["reverted"] = True
        else:
            bad += 1
            log(t("harden.revert_failed", what=a.describe()), YEL)
    if not log.dry:
        snap["reverted"] = bad == 0
        save_snapshot(path, snap)
    return ok, bad


def run_undo(ctx, suite=HARDEN):
    snaps = list_snapshots(suite)
    if not snaps:
        print(f"\n  {GRY}{t('harden.no_snapshots')}{R}")
        return
    items = []
    for p, snap in snaps:
        live = [c for c in snap["changes"] if c.get("ok") and not c.get("reverted")]
        names = ", ".join(sorted({c.get("title") or suite.title(c["rule"]) for c in live}))
        n = sum(1 for c in snap["changes"] if c.get("ok") and not c.get("reverted"))
        items.append(Item("snap", t("harden.snap_title", date=snap.get("date", p.stem), n=n), 0, "opt", names, None,
                          admin=True, tag=t("harden.snap_tag"), key=(p, snap)))
    sel = selector.select(items, ctx.admin or ctx.dry, t("harden.undo_title"), group_label=lambda g: t("harden.snapshots"))
    if not sel:
        return
    if not ctx.dry:
        if not ctx.admin:
            print(f"\n  {YEL}{t('harden.need_admin')}{R}")
            return
        if not is_yes(input(f"\n  {t('harden.confirm_undo', n=len(sel))} "), default=False):
            return
    log = Log(new_log_path(f"{suite.key}_undo"), ctx.dry)
    try:
        for it in sel:
            p, snap = it.key
            section(it.title, term_width())
            ok, bad = revert_snapshot(p, snap, log)
            print(f"  {GRN}{t('harden.undo_done', n=ok)}{R}" + (f"  {YEL}{t('harden.failed_n', n=bad)}{R}" if bad else ""))
    finally:
        log.close()
    print(f"  {YEL}{t('harden.reboot_maybe')}{R}")


# --- Guides ---

def run_guides(ctx, suite=HARDEN):
    W = term_width()
    for g in suite.guides:
        section(t(f"{suite.key}.guide.{g}.title"), W)
        for line in t(f"{suite.key}.guide.{g}.steps").split("\n"):
            print(f"  {line}")


# --- Menu ---

def run(ctx, preselect=None, suite=HARDEN):
    if preselect is not None:
        run_apply(ctx, preselect, suite)
        return
    opts = [dict(key=k, label=suite.tx(f"menu_{k}"), desc=suite.tx(f"menu_{k}.desc"), enabled=True)
            for k in ("apply", "undo", "guides", "back")]
    choice = selector.menu(suite.tx("title"), opts, suite.tx("subtitle"))
    if choice == "apply":
        run_apply(ctx, suite=suite)
    elif choice == "undo":
        run_undo(ctx, suite)
    elif choice == "guides":
        run_guides(ctx, suite)


def fixable(audit_results) -> list:
    """Hardening rule ids that would fix failed or warned audit checks."""
    ids = []
    for r in audit_results:
        if r.status in ("fail", "warn") and r.harden and any(i in BY_ID for i in expand_ids([r.harden])):
            ids.append(r.harden)
    return ids
