"""Resolve the target of a .lnk file (MS-SHLLINK) without COM.

Only the LinkInfo local path is used; advertised MSI shortcuts return None.
"""
import struct

from .fs import lp

HAS_ID_LIST, HAS_LINK_INFO = 0x1, 0x2
LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _cstr(data: bytes, off: int, wide: bool) -> str:
    if wide:
        end = off
        while end + 1 < len(data) and data[end:end + 2] != b"\0\0":
            end += 2
        return data[off:end].decode("utf-16-le", errors="replace")
    end = data.find(b"\0", off)
    raw = data[off:end if end >= 0 else len(data)]
    try:
        return raw.decode("mbcs")
    except (LookupError, UnicodeDecodeError):  # "mbcs" only exists on Windows
        return raw.decode("latin-1")


def parse_lnk(data: bytes):
    if len(data) < 0x4C or data[:4] != b"\x4c\0\0\0" or data[4:20] != LNK_CLSID:
        return None
    flags = struct.unpack_from("<I", data, 0x14)[0]
    off = 0x4C
    if flags & HAS_ID_LIST:
        off += 2 + struct.unpack_from("<H", data, off)[0]
    if not flags & HAS_LINK_INFO or off + 28 > len(data):
        return None
    size, hsize, liflags, _vol, base_off, _net, suffix_off = struct.unpack_from("<7I", data, off)
    if not liflags & 1 or off + size > len(data):  # VolumeIDAndLocalBasePath
        return None
    if hsize >= 0x24:
        base_u, suffix_u = struct.unpack_from("<2I", data, off + 28)
        if base_u:
            return _cstr(data, off + base_u, True) + (_cstr(data, off + suffix_u, True) if suffix_u else "")
    return _cstr(data, off + base_off, False) + (_cstr(data, off + suffix_off, False) if suffix_off else "")


def lnk_target(path):
    try:
        with open(lp(path), "rb") as f:
            return parse_lnk(f.read(65536))
    except OSError:
        return None
