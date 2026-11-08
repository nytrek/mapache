"""Audit report: screen, text and JSON."""
import json
import textwrap
import time

from ... import __version__
from ...core.paths import APP_DIR
from ...i18n import get_lang, t
from ...ui.console import B, CYN, GRN, GRY, MAG, R, RED, YEL, bar, strip_ansi, term_width, trunc
from .checks import CATEGORIES, score

ICONS = {"pass": (GRN, "OK"), "warn": (YEL, "!!"), "fail": (RED, "XX"), "info": (CYN, "i "), "unknown": (GRY, "? ")}
REPORTS = APP_DIR / "reports"


def score_col(s) -> str:
    if s is None:
        return f"{GRY}--{R}"
    col = GRN if s >= 80 else YEL if s >= 50 else RED
    return f"{col}{B}{s}{R}"


def render(results, admin: bool, verbose: bool = True) -> list:
    W = term_width()
    total, per_cat = score(results)
    lines = []
    for cat in CATEGORIES:
        rs = [r for r in results if r.cat == cat]
        if not rs:
            continue
        lines += ["", f"{B}{MAG}▌ {t(f'audit.cat.{cat}')}{R}   {score_col(per_cat[cat])}{GRY}/100{R}",
                  f"{GRY}{'─' * W}{R}"]
        for r in rs:
            col, icon = ICONS[r.status]
            title = t(f"audit.{r.id}.title")
            lines.append(f"  {col}[{icon}]{R} {B}{title}{R}" + (f"  {GRY}{r.detail}{R}" if r.detail else ""))
            if r.status in ("warn", "fail") and verbose:
                for ln in textwrap.wrap(t(f"audit.{r.id}.why"), W - 8):
                    lines.append(f"       {GRY}{ln}{R}")
                for i, ln in enumerate(textwrap.wrap(t(f"audit.{r.id}.fix"), W - 10)):
                    lines.append(f"       {CYN}{'→ ' if i == 0 else '  '}{ln}{R}")
            if r.items and (verbose or r.status in ("warn", "fail")):
                shown = r.items[:8]
                for it in shown:
                    lines.append(f"         {GRY}· {it[:W - 12]}{R}")
                if len(r.items) > len(shown):
                    lines.append(f"         {GRY}{t('audit.more_items', n=len(r.items) - len(shown))}{R}")
            if r.refs and r.status in ("warn", "fail") and verbose:
                lines.append(f"       {GRY}{t('audit.refs')}: {', '.join(r.refs)}{R}")
    counts = {s: sum(1 for r in results if r.status == s) for s in ICONS}
    lines += ["", f"{B}{MAG}▌ {t('audit.summary')}{R}", f"{GRY}{'─' * W}{R}"]
    if total is not None:
        col = GRN if total >= 80 else YEL if total >= 50 else RED
        lines.append(f"  {t('audit.score')}  {bar(total / 100, 30, col)}  {score_col(total)}{GRY}/100{R}")
    lines.append("  " + t("audit.counts", ok=counts["pass"], warn=counts["warn"], fail=counts["fail"],
                          unknown=counts["unknown"], info=counts["info"]))
    # summary of what to fix, shown last so it stays on screen
    todo = sorted((r for r in results if r.status in ("fail", "warn")),
                  key=lambda r: (r.status != "fail", -r.weight, CATEGORIES.index(r.cat)))
    if todo:
        lines += ["", f"  {B}{t('audit.todo')}{R}"]
        for r in todo:
            col, icon = ICONS[r.status]
            title = t(f"audit.{r.id}.title")
            room = W - len(title) - 10
            detail = f"  {GRY}{trunc(r.detail, room)}{R}" if r.detail and room > 15 else ""
            lines.append(f"  {col}[{icon}]{R} {title}{detail}")
        lines.append("")
    if any(r.status == "unknown" and r.admin for r in results) and not admin:
        lines.append(f"  {YEL}{t('audit.run_as_admin')}{R}")
    bl = next((r for r in results if r.id == "bitlocker"), None)
    if bl and bl.status == "fail":
        lines.append(f"  {RED}{B}{t('audit.bitlocker_banner')}{R}")
    lines.append(f"  {GRY}{t('audit.threat_model')}{R}")
    return lines


def export(results, admin: bool, lines: list) -> tuple:
    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    txt, js = REPORTS / f"audit_{stamp}.txt", REPORTS / f"audit_{stamp}.json"
    head = [f"Mapache {__version__} · {t('audit.title')} · {time.strftime('%Y-%m-%d %H:%M')}"
            + (" · admin" if admin else "")]
    txt.write_text("\n".join(strip_ansi(x) for x in head + lines) + "\n", encoding="utf-8")
    total, per_cat = score(results)
    data = dict(app="Mapache", version=__version__, date=time.strftime("%Y-%m-%dT%H:%M:%S"), lang=get_lang(),
                admin=admin, score=total, categories=per_cat,
                results=[dict(id=r.id, category=r.cat, status=r.status, weight=r.weight,
                              title=t(f"audit.{r.id}.title"), detail=r.detail, why=t(f"audit.{r.id}.why"),
                              fix=t(f"audit.{r.id}.fix"), items=r.items, refs=list(r.refs), harden=r.harden)
                         for r in results])
    js.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return txt, js
