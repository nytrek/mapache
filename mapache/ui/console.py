"""Terminal colors, size formatting and display helpers."""
import os
import re
import shutil
import sys
import time

from ..core.paths import DAY, GB, MB
from ..i18n import t


def enable_ansi() -> bool:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass
    return True


COLOR = enable_ansi()


def _c(code):
    return f"\033[{code}m" if COLOR else ""


R, B, REV = _c(0), _c(1), _c(7)
RED, GRN, YEL, BLU, MAG, CYN, GRY = _c(91), _c(92), _c(93), _c(94), _c(95), _c(96), _c(90)

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(s: str) -> str:
    return _ANSI.sub("", s)


def hs(n) -> str:
    if n is None or n < 0:
        return "?"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.2f} TB"


def size_txt(n) -> str:
    """Like hs(), but 0 is shown as an em dash."""
    return "—" if n == 0 else hs(n)


def size_col(n, w: int = 9) -> str:
    if n is None or n < 0:
        return f"{GRY}{'?':>{w}}{R}"
    if n == 0:
        return f"{GRY}{'—':>{w}}{R}"
    col = RED if n >= 10 * GB else YEL if n >= GB else CYN if n >= 100 * MB else GRY
    return f"{col}{hs(n):>{w}}{R}"


def bar(frac: float, width: int = 20, col: str = None) -> str:
    """Bar made of full blocks only (partial blocks render as boxes in common console fonts)."""
    frac = max(0.0, min(1.0, frac))
    s = ("█" * int(round(frac * width))).ljust(width)
    col = col or (RED if frac >= 0.25 else YEL if frac >= 0.10 else BLU)
    return f"{col}{s}{R}"


def trunc(s: str, w: int) -> str:
    if len(s) <= w:
        return s
    if w < 4:
        return s[:w]
    keep = w - 1
    return s[: keep // 2] + "…" + s[-(keep - keep // 2):]


def term_width(cap: int = 130) -> int:
    return min(shutil.get_terminal_size((110, 30)).columns, cap) - 2


def section(title: str, width: int = None):
    width = width or term_width()
    print(f"\n{B}{MAG}▌ {title}{R}")
    print(f"{GRY}{'─' * width}{R}")


def ago(ts) -> str:
    if not ts:
        return t("ago.unknown")
    days = (time.time() - ts) / DAY
    if days < 1:
        return t("ago.today")
    if days < 2:
        return t("ago.yesterday")
    if days < 60:
        return t("ago.days", n=int(days))
    if days < 365:
        return t("ago.months", n=int(days / 30))
    return t("ago.years", n=f"{days / 365:.1f}")


def is_yes(ans: str, default: bool = True) -> bool:
    a = ans.strip().lower()
    if not a:
        return default
    return a in ("s", "si", "sí", "y", "yes")


def pause():
    try:
        input(f"\n  {GRY}{t('common.press_enter')}{R}")
    except EOFError:
        pass
