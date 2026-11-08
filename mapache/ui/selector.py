"""Interactive checkbox list and menu.

Uses msvcrt on Windows and termios elsewhere, with a numbered fallback.
"""
import os
import re
import sys
import textwrap
import unicodedata

from ..i18n import t
from .console import (B, CYN, COLOR, GRN, GRY, MAG, R, REV, YEL, hs, size_col, size_txt,
                      term_width, trunc)


# --- Keyboard ---

def tui_supported() -> bool:
    if not (COLOR and sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    try:
        if os.name == "nt":
            import msvcrt  # noqa: F401
        else:
            import termios  # noqa: F401
            import tty  # noqa: F401
        return True
    except ImportError:
        return False


_WIN_KEYS = {"H": "up", "P": "down", "I": "pgup", "Q": "pgdn", "G": "home", "O": "end",
             "K": "left", "M": "right"}
_ESC_KEYS = {"[A": "up", "[B": "down", "[5~": "pgup", "[6~": "pgdn", "[H": "home", "[F": "end",
             "[1~": "home", "[4~": "end", "OH": "home", "OF": "end", "[D": "left", "[C": "right"}


def read_key() -> str:
    if os.name == "nt":
        import msvcrt
        k = msvcrt.getwch()
        if k in ("\x00", "\xe0"):
            return _WIN_KEYS.get(msvcrt.getwch(), "")
    else:
        import select
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            k = os.read(fd, 1).decode(errors="ignore")
            if k == "\x1b":
                seq = ""
                while len(seq) < 4 and select.select([fd], [], [], 0.03)[0]:
                    seq += os.read(fd, 1).decode(errors="ignore")
                return _ESC_KEYS.get(seq, "esc" if not seq else "")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if k in ("\r", "\n"):
        return "enter"
    if k == "\x1b":
        return "esc"
    if k == " ":
        return "space"
    if k in ("\x08", "\x7f"):
        return "backspace"
    if k == "\x03":
        raise KeyboardInterrupt
    return k


class AltScreen:
    """Alternate screen buffer, restored on exit."""

    def __enter__(self):
        sys.stdout.write("\033[?1049h\033[?25l")
        sys.stdout.flush()
        return self

    def __exit__(self, *exc):
        sys.stdout.write("\033[?25h\033[?1049l")
        sys.stdout.flush()


def _frame(lines: list) -> str:
    return "\033[H" + "\n".join(line + "\033[K" for line in lines) + "\033[J"


def _size() -> tuple:
    import shutil
    cols, rows = shutil.get_terminal_size((110, 30))
    return min(cols, 140), rows


# --- Checkbox list ---

def _fold(s: str) -> str:
    """Lowercase without accents, for search."""
    return "".join(c for c in unicodedata.normalize("NFD", s.lower()) if unicodedata.category(c) != "Mn")


def _view(items: list, query: str, sort) -> list:
    """Visible items: filtered by the search and sorted within each group."""
    q = _fold(query.strip())
    view = [it for it in items if not q or q in _fold(f"{it.title} {it.tag} {it.note}")]
    if sort:
        gorder = {}
        for it in items:
            gorder.setdefault(it.group, len(gorder))
        # stable sort: by key, then by group
        view = sorted(sorted(view, key=sort[1]), key=lambda it: gorder[it.group])
    return view


def _build_rows(items: list) -> list:
    rows, group = [], None
    for i, it in enumerate(items):
        if it.group != group:
            if rows:
                rows.append(("b", None))
            rows.append(("g", it.group))
            group = it.group
        rows.append(("i", i))
    return rows


def _header(items, sel) -> str:
    """Selected size and count, or only the count when no item has a size."""
    if all(it.size <= 0 for it in items):
        return t("sel.header_count", n=f"{GRN}{B}{len(sel)}{R}", m=len(items))
    total = sum(max(it.size, 0) for it in sel)
    return t("sel.header", size=f"{GRN}{B}{hs(total)}{R}", n=len(sel), m=len(items))


def _tag_width(items) -> int:
    tags = [len(it.tag) for it in items if it.tag]
    return min(28, max(tags)) if tags else 11


def _item_line(it, admin: bool, W: int, current: bool, tagw: int = 11) -> str:
    lock = f" {t('sel.admin_tag')}" if it.admin and not admin else ""
    tw = max(15, W - 48 - tagw)
    title = trunc(it.title, tw)
    tag = trunc(it.tag, tagw) if it.tag else (t("sel.rec") if it.level == "rec" else t("sel.opt"))
    box = "[x]" if it.selected else "[ ]"
    if current:
        plain = f" > {box} {size_txt(it.size):>9}  {title:<{tw}}  {tag:<{tagw}}{lock}"
        return f"{REV}{B}{plain[:W - 1].ljust(W - 1)}{R}"
    boxc = f"{GRN}{B}[x]{R}" if it.selected else f"{GRY}[ ]{R}"
    if it.tag:
        tagc = f"{GRY}{tag:<{tagw}}{R}"
    else:
        tagc = f"{GRN}{tag:<{tagw}}{R}" if it.level == "rec" else f"{CYN}{tag:<{tagw}}{R}"
    lockc = f"{YEL}{lock}{R}" if lock else ""
    return f"   {boxc} {size_col(it.size)}  {title:<{tw}}  {tagc}{lockc}"


def _render_list(items, view, rows, item_rows, cur, off, vh, W, admin, msg, title, group_label,
                 query="", searching=False, sort_label="", tagw=11) -> str:
    sel = [it for it in items if it.selected]
    head = f" {B}{CYN}{title}{R}   " + _header(items, sel)
    extra = []
    if searching or query:
        extra.append(f"{YEL}{t('sel.search')}: {B}{query}{'▏' if searching else ''}{R}"
                     + (f" {GRY}({len(view)}){R}" if query else ""))
    if sort_label:
        extra.append(f"{GRY}{t('sel.sorted_by', by=sort_label)}{R}")
    if extra:
        head += "   " + "  ·  ".join(extra)
    lines = [head,
             f"{GRY}{'─' * (W - 1)}{R}" if off == 0 else f"{GRY}{'─' * (W - 14)} {t('sel.more_up')}{R}"]
    crow = item_rows[cur] if item_rows else -1
    for r in range(off, min(off + vh, len(rows))):
        kind, val = rows[r]
        if kind == "g":
            lines.append(f" {B}{MAG}▌ {group_label(val)}{R}")
        elif kind == "b":
            lines.append("")
        else:
            lines.append(_item_line(view[val], admin, W, r == crow, tagw))
    if not rows:
        lines.append(f"   {GRY}{t('sel.no_results')}{R}")
    lines += [""] * (vh - (len(lines) - 2))
    more = off + vh < len(rows)
    lines.append(f"{GRY}{'─' * (W - 14)} {t('sel.more_down')}{R}" if more else f"{GRY}{'─' * (W - 1)}{R}")
    note = textwrap.wrap(view[rows[crow][1]].note, max(30, W - 4))[:3] if item_rows else []
    note += [""] * (3 - len(note))
    lines += [f"  {GRY}{line}{R}" for line in note]
    lines.append(f"  {YEL}{msg}{R}" if msg else "")
    helpers = t("sel.help_search") + (" · " + t("sel.help_sort") if sort_label else "")
    lines.append(f"  {B}{trunc(t('sel.help'), W - 3)}{R}")
    lines.append(f"  {GRY}{trunc(t('sel.help_searching') if searching else helpers, W - 3)}{R}")
    return _frame(lines)


def _bulk(items, admin, mode) -> str:
    for it in items:
        it.selected = (admin or not it.admin) and (mode == "t" or (mode == "r" and it.level == "rec"))
    n = sum(it.selected for it in items)
    return {"r": t("sel.marked_rec", n=n), "t": t("sel.marked_all", n=n), "n": t("sel.marked_none")}[mode]


def _select_tui(items, admin, title, group_label, sorts) -> list:
    cur, off, msg = 0, 0, ""
    query, searching, sort_i = "", False, 0
    tagw = _tag_width(items)
    with AltScreen():
        while True:
            sort = sorts[sort_i] if sorts else None
            view = _view(items, query, sort)
            rows = _build_rows(view)
            item_rows = [r for r, (k, _) in enumerate(rows) if k == "i"]
            n = len(item_rows)
            W, H = _size()
            vh = max(5, H - 11)
            cur = max(0, min(cur, n - 1))
            if n:
                crow = item_rows[cur]
                top = crow - 1 if crow > 0 and rows[crow - 1][0] == "g" else crow
                if top < off:
                    off = top
                if crow >= off + vh:
                    off = crow - vh + 1
            off = max(0, min(off, max(0, len(rows) - vh)))
            sys.stdout.write(_render_list(items, view, rows, item_rows, cur, off, vh, W, admin, msg, title,
                                          group_label, query, searching, sort[0] if sort else "", tagw))
            sys.stdout.flush()
            msg = ""
            k = read_key()
            page = max(1, vh // 2)
            if searching:  # while typing, keys go to the search box
                if k == "enter":
                    searching = False
                elif k == "esc":
                    searching, query, cur, off = False, "", 0, 0
                elif k == "backspace":
                    query, cur, off = query[:-1], 0, 0
                elif k == "space":
                    query += " "
                elif len(k) == 1 and k.isprintable():
                    query, cur, off = query + k, 0, 0
                elif k == "up":
                    cur = max(0, cur - 1)
                elif k == "down":
                    cur = min(n - 1, cur + 1)
                continue
            if k in ("up", "k"):
                cur = max(0, cur - 1)
            elif k in ("down", "j"):
                cur = min(n - 1, cur + 1)
            elif k == "pgup":
                cur = max(0, cur - page)
            elif k == "pgdn":
                cur = min(n - 1, cur + page)
            elif k == "home":
                cur = 0
            elif k == "end":
                cur = n - 1
            elif k == "/":
                searching = True
            elif k in ("o", "O") and sorts:
                sort_i = (sort_i + 1) % len(sorts)
                cur, off = 0, 0
                msg = t("sel.sorted_by", by=sorts[sort_i][0])
            elif k in ("x", "X", "space") and n:
                it = view[rows[item_rows[cur]][1]]
                if it.admin and not admin:
                    msg = t("sel.needs_admin", title=it.title)
                else:
                    it.selected = not it.selected
            elif k.lower() in ("r", "t", "n") and len(k) == 1:
                msg = _bulk(view, admin, k.lower())
            elif k == "enter":
                return [it for it in items if it.selected]
            elif k == "esc" and query:
                query, cur, off = "", 0, 0
            elif k in ("esc", "q", "Q"):
                return []


def _parse_sel(s: str, n: int):
    out = set()
    for tok in re.split(r"[,\s]+", s.strip()):
        if not tok:
            continue
        m = re.fullmatch(r"(\d+)-(\d+)", tok)
        if m:
            a, b = map(int, m.groups())
            out |= set(range(min(a, b), max(a, b) + 1))
        elif tok.isdigit():
            out.add(int(tok))
        else:
            return None
    return {i for i in out if 1 <= i <= n}


def _select_numbers(items, admin, title, group_label, sorts) -> list:
    msg, query, sort_i = "", "", 0
    tagw = _tag_width(items)
    while True:
        W = term_width()
        sort = sorts[sort_i] if sorts else None
        view = _view(items, query, sort)
        print(f"\n {B}{CYN}{title}{R}" + (f"   {YEL}{t('sel.search')}: {query}{R}" if query else "")
              + (f"   {GRY}{t('sel.sorted_by', by=sort[0])}{R}" if sort else ""))
        group = None
        for i, it in enumerate(view, 1):
            if it.group != group:
                group = it.group
                print(f"\n{B}{MAG}▌ {group_label(group)}{R}")
            print(f"  {i:>3}" + _item_line(it, admin, W - 3, False, tagw)[2:])
            for line in textwrap.wrap(it.note, max(30, W - 18))[:3]:
                print(f"{' ' * 18}{GRY}{line}{R}")
        if not view:
            print(f"   {GRY}{t('sel.no_results')}{R}")
        sel = [it for it in items if it.selected]
        print("\n  " + _header(items, sel))
        if msg:
            print(f"  {YEL}{msg}{R}")
        print(f"  {GRY}{t('sel.num_help')}{R}")
        print(f"  {GRY}{t('sel.num_help_search')}" + (f" · {t('sel.num_help_sort')}" if sorts else "") + R)
        s = input(f"  {CYN}>{R} ").strip()
        msg = ""
        if s == "":
            return sel
        if s.startswith("/"):
            query = s[1:]
            continue
        s = s.lower()
        if s == "q":
            return []
        if s == "o" and sorts:
            sort_i = (sort_i + 1) % len(sorts)
            continue
        if s in ("r", "t", "n"):
            msg = _bulk(view, admin, s)
            continue
        nums = _parse_sel(s, len(view))
        if nums is None:
            msg = t("sel.bad_input")
            continue
        for k in nums:
            it = view[k - 1]
            if it.admin and not admin:
                msg = t("sel.needs_admin", title=it.title)
            else:
                it.selected = not it.selected


def select(items: list, admin: bool, title: str, group_label=lambda g: g, sorts=None) -> list:
    """Show the list and return the items the user selected.

    sorts: [(label, key function)], cycled with `o`.
    """
    if tui_supported():
        input(f"  {B}{t('sel.open')}{R}")
        return _select_tui(items, admin, title, group_label, sorts)
    return _select_numbers(items, admin, title, group_label, sorts)


# --- Menu ---

def _render_menu(title, subtitle, options, cur, W, msg) -> str:
    lines = [f" {B}{CYN}{title}{R}  {GRY}{subtitle}{R}", f"{GRY}{'─' * (W - 1)}{R}", ""]
    for i, o in enumerate(options):
        label = o["label"] + ("" if o["enabled"] else f"  ({t('menu.soon')})")
        plain = f" > {i + 1:>2}  {label}"
        if i == cur:
            lines.append(f"{REV}{B}{plain[:W - 1].ljust(W - 1)}{R}")
        elif o["enabled"]:
            lines.append(f"   {GRY}{i + 1:>2}{R}  {label}")
        else:
            lines.append(f"   {GRY}{i + 1:>2}  {label}{R}")
    lines += ["", f"{GRY}{'─' * (W - 1)}{R}"]
    desc = textwrap.wrap(options[cur].get("desc", ""), max(30, W - 4))[:3]
    desc += [""] * (3 - len(desc))
    lines += [f"  {GRY}{line}{R}" for line in desc]
    lines.append(f"  {YEL}{msg}{R}" if msg else "")
    lines.append(f"  {B}{t('menu.help')}{R}")
    return _frame(lines)


def menu(title: str, options: list, subtitle: str = "", start: int = 0):
    """options: [{key, label, desc, enabled}]. Return the chosen key or None."""
    if not tui_supported():
        print(f"\n {B}{CYN}{title}{R}  {GRY}{subtitle}{R}")
        for i, o in enumerate(options, 1):
            soon = "" if o["enabled"] else f" {GRY}({t('menu.soon')}){R}"
            print(f"  {i:>2}. {o['label']}{soon}")
        while True:
            s = input(f"  {CYN}>{R} ").strip()
            if not s:
                return None
            if s.isdigit() and 1 <= int(s) <= len(options):
                o = options[int(s) - 1]
                if o["enabled"]:
                    return o["key"]
                print(f"  {YEL}{t('menu.soon_msg')}{R}")

    cur, msg = min(start, len(options) - 1), ""
    with AltScreen():
        while True:
            W, _ = _size()
            sys.stdout.write(_render_menu(title, subtitle, options, cur, W, msg))
            sys.stdout.flush()
            msg = ""
            k = read_key()
            if k in ("up", "k"):
                cur = (cur - 1) % len(options)
            elif k in ("down", "j"):
                cur = (cur + 1) % len(options)
            elif k == "home":
                cur = 0
            elif k == "end":
                cur = len(options) - 1
            elif k.isdigit() and 1 <= int(k) <= len(options):
                cur = int(k) - 1
                if options[cur]["enabled"]:
                    return options[cur]["key"]
                msg = t("menu.soon_msg")
            elif k == "enter":
                if options[cur]["enabled"]:
                    return options[cur]["key"]
                msg = t("menu.soon_msg")
            elif k in ("esc", "q", "Q"):
                return None
