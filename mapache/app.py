"""Entry point: arguments, elevation and main menu."""
import argparse
import os
import sys

from . import APP_NAME, __version__, config, i18n
from .core.ctx import Ctx
from .core.elevate import is_admin, relaunch_admin
from .i18n import t
from .modules import audit, cleaner, diskreport, harden, optimize, privacy, programs
from .ui import selector
from .ui.console import GRN, R, YEL, is_yes, pause

MODULES = {
    "clean": cleaner.run,
    "disk": diskreport.run,
    "programs": programs.run,
    "audit": audit.run,
    "harden": harden.run,
    "privacy": privacy.run,
    "optimize": optimize.run,
}

# (key, enabled). Disabled entries are shown as "coming soon".
MENU = [
    ("clean", True),
    ("disk", True),
    ("programs", True),
    ("audit", True),
    ("harden", True),
    ("privacy", True),
    ("optimize", True),
    ("lang", True),
    ("exit", True),
]


def choose_lang():
    opts = [dict(key=code, label=name, desc="", enabled=True) for code, name in i18n.LANGS.items()]
    start = list(i18n.LANGS).index(i18n.get_lang())
    choice = selector.menu(t("lang.title"), opts, start=start)
    if choice:
        i18n.set_lang(choice)
        config.save(lang=choice)


def main_menu(ctx: Ctx):
    last = 0
    while True:
        opts = [dict(key=k, label=t(f"menu.{k}"), desc=t(f"menu.{k}.desc"), enabled=en) for k, en in MENU]
        sub = f"v{__version__} · " + (t("app.admin") if ctx.admin else t("app.no_admin"))
        if ctx.dry:
            sub += " · " + t("app.simulation")
        choice = selector.menu(APP_NAME.upper(), opts, sub, start=last)
        if choice in (None, "exit"):
            return
        last = [k for k, _ in MENU].index(choice)
        if choice == "lang":
            choose_lang()
            continue
        MODULES[choice](ctx)
        pause()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mapache", description=f"{APP_NAME} {__version__}")
    ap.add_argument("command", nargs="?", choices=sorted(MODULES),
                    help="clean = free space, disk = disk usage report, programs = uninstaller, audit = security audit, harden = reversible hardening, privacy = telemetry/ads/browser policies, optimize = startup/tasks/power")
    ap.add_argument("--lang", choices=sorted(i18n.LANGS), help="es | en")
    ap.add_argument("--simulate", "--simular", dest="simulate", action="store_true",
                    help="dry run: show what would happen without changing anything")
    ap.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    i18n.set_lang(args.lang or config.load().get("lang") or i18n.detect_lang())
    if os.name != "nt":
        sys.exit(t("app.windows_only"))

    admin = is_admin()
    if not admin and not args.elevated:
        if is_yes(input(f"  {t('app.ask_admin')} ")):
            extra = ([args.command] if args.command else []) + ["--lang", i18n.get_lang()]
            if args.simulate:
                extra.append("--simulate")
            if relaunch_admin(extra):
                print(f"  {GRN}{t('app.elevated_opened')}{R}")
                return
            print(f"  {YEL}{t('app.elevate_failed')}{R}")

    ctx = Ctx(admin, dry=args.simulate)
    try:
        if args.command:
            MODULES[args.command](ctx)
        else:
            main_menu(ctx)
    except KeyboardInterrupt:
        print(f"\n  {YEL}{t('common.cancelled')}{R}")
    if args.elevated:
        try:
            input(f"\n  {t('common.press_enter_close')}")
        except EOFError:
            pass
