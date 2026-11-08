"""Read-only security audit with a score."""
import time

from ...i18n import t
from ...ui.console import B, GRN, GRY, R, is_yes
from .checks import run_all
from .facts import Facts
from .report import export, render


def run(ctx):
    print(f"\n  {B}{t('audit.collecting')}{R} {GRY}{t('audit.readonly')}{R}")
    t0 = time.perf_counter()
    facts = Facts(ctx.admin).collect()
    results = run_all(facts)
    print(f"  {GRY}{t('audit.done_in', n=len(results), s=f'{time.perf_counter() - t0:.1f}')}{R}")
    lines = render(results, ctx.admin)
    print("\n".join(lines))
    try:
        ans = input(f"\n  {t('audit.ask_export')} ")
    except EOFError:
        return
    if is_yes(ans):
        txt, js = export(results, ctx.admin, lines)
        print(f"  {GRN}{t('audit.exported')}{R}\n  {GRY}{txt}\n  {js}{R}")
    # offer Hardening for findings that have a reversible fix
    from ..harden import fixable, run as harden_run
    ids = sorted(set(fixable(results)))
    if ids:
        print(f"\n  {B}{t('audit.can_fix', n=len(ids))}{R}")
        try:
            if is_yes(input(f"  {t('audit.ask_fix')} "), default=False):
                harden_run(ctx, preselect=ids)
        except EOFError:
            pass
