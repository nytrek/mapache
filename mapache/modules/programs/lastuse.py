"""Last use of programs from two Windows artifacts.

UserAssist: per-user launch counts and times, value names in ROT13. No admin needed.
Prefetch: last 8 runs and run count per executable, MAM-compressed on Windows 10/11. Needs admin.
Both can be cleared or disabled, so missing data does not mean never used.
"""
import codecs
import ctypes
import os
import re
import struct
import time

from ...core.fs import is_under, lp
from ...core.lnk import lnk_target
from ...core.paths import HOME, LOCAL, PD, PF, PF86, ROAMING, WIN
from ...core.winreg_util import reg_subkeys, reg_values, winreg

UA_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
PREFETCH = WIN / "Prefetch"
EPOCH_DIFF = 11644473600  # seconds between 1601 (FILETIME) and 1970 (Unix)

# Known Folder GUIDs at the start of UserAssist paths
KNOWN = {
    "{6D809377-6AF0-444B-8957-A3773F02200E}": PF,
    "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": PF,
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": PF86,
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": WIN,
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": WIN / "System32",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": WIN / "SysWOW64",
    "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": LOCAL,
    "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": ROAMING,
    "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": HOME,
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": PD / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": ROAMING / "Microsoft" / "Windows" / "Start Menu" / "Programs",
}

# running the uninstaller, installer or crash reporter is not using the program
NOT_USE = re.compile(r"^(unins|uninst|uninstall|setup|install|crashpad|crashreporter|crashhandler|"
                     r"werfault|update(r)?\.exe$|maintenancetool)", re.I)


def filetime(ft: int) -> float:
    ts = ft / 1e7 - EPOCH_DIFF if ft else 0.0
    return ts if 0 < ts < time.time() + 86400 else 0.0


# --- UserAssist ---

def decode_userassist(name: str, data: bytes):
    """(path, last use, count) from a UserAssist value (Windows 7+ format)."""
    path = codecs.decode(name, "rot13")
    if not isinstance(data, (bytes, bytearray)) or len(data) < 68:
        return path, 0.0, 0
    count = struct.unpack_from("<I", data, 4)[0]
    last = filetime(struct.unpack_from("<Q", data, 60)[0])
    return path, last, count


def expand_known(path: str) -> str:
    m = re.match(r"(\{[0-9A-Fa-f-]{36}\})(.*)", path)
    if m and m.group(1).upper() in KNOWN:
        return str(KNOWN[m.group(1).upper()]) + m.group(2)
    return path


def userassist() -> list:
    """[(path or AppUserModelID, last use, count)]. Shortcuts are resolved to their target."""
    out = []
    if winreg is None:
        return out
    hk = winreg.HKEY_CURRENT_USER
    for guid in reg_subkeys(hk, UA_KEY):
        for name, data in reg_values(hk, f"{UA_KEY}\\{guid}\\Count").items():
            path, last, count = decode_userassist(name, data)
            if not last and not count:
                continue
            path = expand_known(path)
            if path.lower().endswith(".lnk"):
                path = lnk_target(path) or path
            out.append((path, last, count))
    return out


# --- Prefetch ---

def mam_decompress(data: bytes) -> bytes:
    """Decompress a Windows 10/11 .pf file (MAM header, Xpress Huffman)."""
    if data[:3] != b"MAM":
        return data
    algo, usize = data[3] & 0x0F, struct.unpack_from("<I", data, 4)[0]
    hdr = 12 if data[3] & 0xF0 else 8  # the header is 4 bytes longer when it has a checksum
    if algo != 4 or not 0 < usize < 64 * 1024 * 1024:  # COMPRESSION_FORMAT_XPRESS_HUFF
        raise ValueError("unsupported MAM")
    ntdll = ctypes.WinDLL("ntdll")
    ws_buf, ws_frag = ctypes.c_ulong(), ctypes.c_ulong()
    st = ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(algo), ctypes.byref(ws_buf), ctypes.byref(ws_frag))
    if st:
        raise OSError(f"RtlGetCompressionWorkSpaceSize 0x{st & 0xFFFFFFFF:08X}")
    ws = ctypes.create_string_buffer(max(ws_frag.value, 1))
    out = ctypes.create_string_buffer(usize)
    src = data[hdr:]
    final = ctypes.c_ulong()
    st = ntdll.RtlDecompressBufferEx(ctypes.c_ushort(algo), out, ctypes.c_ulong(usize), src,
                                     ctypes.c_ulong(len(src)), ctypes.byref(final), ws)
    if st:
        raise OSError(f"RtlDecompressBufferEx 0x{st & 0xFFFFFFFF:08X}")
    return out.raw[:final.value]


def parse_prefetch(data: bytes) -> dict:
    """Executable, last runs, run count and full path (versions 26, 30 and 31)."""
    if len(data) < 0xD4 or data[4:8] != b"SCCA":
        raise ValueError("not SCCA")
    ver = struct.unpack_from("<I", data, 0)[0]
    exe = data[0x10:0x4C].decode("utf-16-le", errors="ignore").split("\0")[0]
    if ver not in (26, 30, 31):
        raise ValueError(f"version {ver}")
    runs = [filetime(x) for x in struct.unpack_from("<8Q", data, 0x80)]
    runs = sorted((r for r in runs if r), reverse=True)
    metrics_off = struct.unpack_from("<I", data, 0x54)[0]
    count = struct.unpack_from("<I", data, 0xC8 if ver >= 30 and metrics_off == 0x12C else 0xD0)[0]
    fn_off, fn_size = struct.unpack_from("<2I", data, 0x64)
    path = ""
    if 0 < fn_off < len(data) and fn_size:
        names = data[fn_off:fn_off + fn_size].decode("utf-16-le", errors="ignore").split("\0")
        up = exe.upper()
        path = next((n for n in names if n.upper().endswith("\\" + up)), "") or \
            next((n for n in names if n.upper().rsplit("\\", 1)[-1].startswith(up)), "")
        # strip the \VOLUME{...} prefix
        path = re.sub(r"^\\(VOLUME|DEVICE\\HARDDISKVOLUME)[^\\]*", "", path, flags=re.I)
    return dict(exe=exe, runs=runs, last=runs[0] if runs else 0.0, count=count, path=path)


def prefetch() -> list:
    """[dict(exe, last, count, path)] for every readable .pf (empty without admin)."""
    out = []
    try:
        entries = list(os.scandir(lp(PREFETCH)))
    except OSError:
        return out
    for e in entries:
        if not e.name.lower().endswith(".pf"):
            continue
        try:
            mt = e.stat().st_mtime
            with open(e.path, "rb") as f:
                info = parse_prefetch(mam_decompress(f.read()))
        except (OSError, ValueError):
            # not decompressible: at least the name and the file date
            try:
                info = dict(exe=e.name.rsplit("-", 1)[0], last=mt, count=0, path="")
            except OSError:
                continue
        out.append(info)
    return out


# --- Matching ---

def _strip_drive(p: str) -> str:
    return os.path.splitdrive(p)[1].rstrip("\\").upper()


POLICY_EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
PREFETCH_PARAMS = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"


def userassist_disabled() -> bool:
    """True if the NoInstrumentation policy disables UserAssist."""
    if winreg is None:
        return False
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        if reg_values(hive, POLICY_EXPLORER).get("NoInstrumentation") == 1:
            return True
    return False


def prefetch_disabled() -> bool:
    if winreg is None:
        return False
    return reg_values(winreg.HKEY_LOCAL_MACHINE, PREFETCH_PARAMS).get("EnablePrefetcher") == 0


def assign(programs: list, admin: bool) -> dict:
    """Fill prog.last_used, prog.runs and prog.lu_src.

    Return the status of each source: ok | empty | disabled | no_admin.
    """
    ua = userassist()
    pf = prefetch() if admin else []
    status = {
        "userassist": "ok" if ua else "disabled" if userassist_disabled() else "empty",
        "prefetch": "ok" if pf else "disabled" if prefetch_disabled() else "no_admin" if not admin else "empty",
    }
    for prog in programs:
        best, runs, src = 0.0, 0, ""
        loc = prog.location
        if loc:
            nloc = _strip_drive(loc)
            for path, last, count in ua:
                if NOT_USE.match(os.path.basename(path)) or not is_under(path, loc):
                    continue
                runs += count
                if last > best:
                    best, src = last, "userassist"
            for info in pf:
                if not info["path"] or NOT_USE.match(info["exe"]):
                    continue
                p = info["path"].upper()
                if p == nloc or p.startswith(nloc + "\\"):
                    runs = max(runs, info["count"])
                    if info["last"] > best:
                        best, src = info["last"], "prefetch"
        if prog.aumid_prefix:  # Store apps are recorded by AppUserModelID
            for path, last, count in ua:
                if path.lower().startswith(prog.aumid_prefix):
                    runs += count
                    if last > best:
                        best, src = last, "userassist"
        prog.last_used, prog.runs, prog.lu_src = best, runs, src
    return status
