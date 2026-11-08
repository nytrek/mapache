"""Disk usage report (read-only)."""
import os
import shutil

from ..core.fs import disp, is_under
from ..core.paths import GB, MB, PD, USERS
from ..i18n import t
from ..ui.console import (B, BLU, CYN, GRN, GRY, MAG, R, RED, YEL, bar, hs, section, size_col,
                          term_width, trunc)


def _base(p) -> str:
    return os.path.basename(str(p).rstrip("\\/")) or disp(p)


def report_header(sc, W):
    root = disp(sc.root)
    section(t("disk.summary", root=root), W)
    du = None
    try:
        du = shutil.disk_usage(root)
        frac = du.used / du.total
        print(f"  {t('disk.usage'):<14} {bar(frac, 40)}  {B}{frac * 100:.0f}%{R}")
        print("  " + t("disk.totals", total=f"{B}{hs(du.total)}{R}", used=f"{B}{hs(du.used)}{R}",
                       free=f"{GRN}{B}{hs(du.free)}{R}"))
    except OSError:
        pass
    rate = sc.files_count / sc.elapsed if sc.elapsed else 0
    print(f"  {t('disk.analyzed'):<14} " + t("disk.analyzed_line", size=f"{B}{hs(sc.scanned)}{R}",
                                                files=f"{sc.files_count:,}", dirs=f"{sc.dirs_count:,}")
          + f" {GRY}({sc.elapsed:.1f}s · {rate:,.0f} {t('disk.files_per_s')}){R}")
    _, rest = os.path.splitdrive(root)
    if du and rest in ("\\", "/", ""):
        missing = du.used - sc.scanned
        if missing > GB:
            print(f"  {YEL}{t('disk.unaccounted', size=hs(missing))}{R}")
            print(f"  {GRY}  {t('disk.unaccounted_why')}{R}")
    if sc.cloud_bytes > 100 * MB:
        print(f"  {CYN}{t('disk.cloud', size=hs(sc.cloud_bytes))}{R}")


def report_tree(sc, W):
    section(t("disk.tree"), W)
    total, children = sc.total, sc.children
    scanned = max(sc.scanned, 1)
    min_show = max(50 * MB, scanned * 0.002)
    expand = max(1 * GB, scanned * 0.02)
    limits = (14, 6, 4, 3)
    name_w = max(26, min(60, W - 46))

    def line(prefix, con, name, size):
        nw = max(10, name_w - len(prefix) - len(con))
        print(f"  {GRY}{prefix}{con}{R}{trunc(name, nw):<{nw}} {size_col(size, 10)} "
              f"{GRY}{size * 100 / scanned:5.1f}%{R} {bar(size / scanned)}")

    def walk(node, prefix, depth):
        kids = sorted(children.get(node, ()), key=lambda k: total.get(k, 0), reverse=True)
        shown = [k for k in kids[: limits[depth]] if total.get(k, 0) >= min_show]
        rest = total.get(node, 0) - sum(total[k] for k in shown)
        for idx, k in enumerate(shown):
            last = idx == len(shown) - 1 and rest < min_show
            line(prefix, "└─ " if last else "├─ ", _base(k), total[k])
            if depth + 1 < len(limits) and total[k] >= expand and children.get(k):
                walk(k, prefix + ("   " if last else "│  "), depth + 1)
        if rest >= min_show and shown:
            nw = max(10, name_w - len(prefix) - 3)
            print(f"  {GRY}{prefix}└─ {trunc(t('disk.others'), nw):<{nw}}{R} {size_col(rest, 10)}")

    print(f"  {B}{disp(sc.root)}{R}")
    walk(sc.root, "", 0)


GAME_ROOTS = {
    "common": [("\\steamapps\\common", "Steam")],
    "epic games": [("\\epic games", "Epic")],
    "riot games": [("\\riot games", "Riot")],
    "xboxgames": [("\\xboxgames", "Xbox")],
    "ea games": [("\\ea games", "EA")],
    "electronic arts": [("\\electronic arts", "EA")],
    "games": [("\\ubisoft game launcher\\games", "Ubisoft"), ("\\gog galaxy\\games", "GOG")],
    "gog games": [("\\gog games", "GOG")],
    "rockstar games": [("\\rockstar games", "Rockstar")],
}
NOT_GAMES = {"launcher", "directxredist", "steamworks shared", "epic online services", "rockstar games launcher",
             "social club", "riot client", "eaapp", "ea desktop", "eosoverlay", "gamesave",
             "steam controller configs"}


def find_games(sc) -> list:
    found = []
    for p, par in sc.parent.items():
        if par is None:
            continue
        cands = GAME_ROOTS.get(_base(par).lower())
        if not cands:
            continue
        # game saves and settings under user folders are not games
        if is_under(par, USERS) or is_under(par, PD):
            continue
        pl = disp(par).lower()
        for suf, label in cands:
            if pl.endswith(suf) and _base(p).lower() not in NOT_GAMES and not _base(p).upper().startswith("UE_"):
                found.append((sc.total.get(p, 0), _base(p), label, p))
                break
    found.sort(reverse=True)
    return found


def report_games(sc, W, top):
    found = [g for g in find_games(sc) if g[0] >= 10 * MB]
    if not found:
        return
    tot = sum(f[0] for f in found)
    section(t("disk.games", n=len(found), size=hs(tot)), W)
    biggest = found[0][0] or 1
    name_w = max(20, min(44, W - 50))
    for size, name, label, _ in found[:top]:
        print(f"  {trunc(name, name_w):<{name_w}} {GRY}{label:<9}{R}{size_col(size, 10)}  "
              f"{bar(size / biggest, 18, MAG)}")
    if len(found) > top:
        print(f"  {GRY}{t('disk.and_more', n=len(found) - top, size=hs(sum(f[0] for f in found[top:])))}{R}")


CATEGORIES = [
    ("vm", "vhd vhdx avhdx vmdk vdi qcow2 ova ovf vmem vmsn nvram", MAG),
    ("video", "mp4 mkv avi mov wmv flv webm m4v ts mts 3gp", RED),
    ("image", "jpg jpeg png gif bmp webp heic tif tiff psd raw cr2 nef arw dng svg ico", YEL),
    ("audio", "mp3 wav flac aac ogg m4a wma opus", GRN),
    ("archive", "zip rar 7z tar gz tgz xz bz2 zst iso img cab nsp xci", CYN),
    ("gamedata", "pak vpk bundle assets resource resources bsa ba2 forge wad big rpf ucas utoc cas scs tfc", MAG),
    ("ai", "gguf safetensors ckpt pt pth onnx", BLU),
    ("program", "exe dll sys msi msix msp appx appxbundle ocx mui", BLU),
    ("doc", "pdf doc docx xls xlsx ppt pptx odt ods txt csv md epub", GRN),
    ("cache", "tmp temp log etl cache dmp", GRY),
    ("db", "db sqlite sqlite3 ldb mdb edb", CYN),
]


def report_types(sc, W):
    merged = sc.ext_totals()
    ext_to_cat = {}
    for cid, exts, _ in CATEGORIES:
        for x in exts.split():
            ext_to_cat.setdefault(x, cid)
    cats = {}
    for x, v in merged.items():
        cid = ext_to_cat.get(x, "other")
        cats[cid] = cats.get(cid, 0) + v
    colors = {cid: col for cid, _, col in CATEGORIES}
    section(t("disk.types"), W)
    scanned = max(sc.scanned, 1)
    for cid, size in sorted(cats.items(), key=lambda kv: kv[1], reverse=True):
        if size < 10 * MB:
            continue
        col = colors.get(cid, GRY)
        print(f"  {col}■{R} {t('cat.' + cid):<28}{size_col(size, 10)} {GRY}{size * 100 / scanned:5.1f}%{R} "
              f"{bar(size / scanned, 24, col)}")
    top_ext = sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:10]
    print(f"\n  {GRY}{t('disk.top_ext')}{R} " + "  ".join(
        f"{B}.{x or t('disk.no_ext')}{R} {GRY}{hs(v)}{R}" for x, v in top_ext))


def report_files(sc, W, top):
    biggest = sc.top_files(top)
    if not biggest:
        return
    section(t("disk.top_files", n=len(biggest)), W)
    path_w = max(30, W - 16)
    for size, path in biggest:
        p = disp(path)
        folder, name = os.path.split(p)
        room = path_w - len(name) - 1
        folder = folder if folder.endswith(os.sep) else folder + os.sep  # drive roots already end with a separator
        shown = (trunc(folder, room) if room > 8 else "") + f"{B}{name}{R}"
        print(f"  {size_col(size, 10)}  {GRY}{shown}{R}")


def report_denied(sc, admin, W):
    if not sc.denied:
        return
    section(t("disk.denied", n=f"{len(sc.denied):,}"), W)
    for p in sorted(sc.denied, key=len)[:5]:
        print(f"  {GRY}{disp(p)}{R}")
    if not admin:
        print(f"  {YEL}{t('disk.run_as_admin')}{R}")


def run(ctx, top: int = 15):
    W = term_width()
    sc = ctx.ensure_scan()
    report_header(sc, W)
    report_tree(sc, W)
    report_games(sc, W, top)
    report_types(sc, W)
    report_files(sc, W, top)
    report_denied(sc, ctx.admin, W)
    print(f"\n  {GRY}{t('disk.hint_clean')}{R}")
