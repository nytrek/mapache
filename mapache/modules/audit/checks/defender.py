"""Microsoft Defender: real-time protection, signatures, tamper protection, exclusions, ASR and PUA."""
import re

from ....i18n import t
from ..facts import as_list, is_true
from . import R, check

ADMIN_NA = "must be an administrator"
# Exclusions commonly added by malware: user-writable folders, whole drives,
# interpreters/LOLBins and executable extensions
SUSP_PATH = re.compile(r"^[a-z]:\\?$|\\users\\|\\appdata\\|\\temp\\|\\downloads|\\descargas|\\programdata\\?$|"
                       r"\\programdata\\[^\\]+\\?$|\\public\\|\*", re.I)
SUSP_PROC = re.compile(r"(^|\\)(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|"
                       r"msbuild|installutil|python|node|java)(\.exe)?$", re.I)
SUSP_EXT = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "jse", "scr", "hta", "msi", "lnk", "com", "pif",
            "wsf", "jar", "zip", "rar", "7z", "iso"}


def other_av(f) -> str:
    """Name of an active third-party antivirus, or ''."""
    for p in as_list(f.psv("av")):
        name, state = str(p.get("displayName", "")), int(p.get("productState") or 0)
        if "defender" not in name.lower() and state & 0x1000:
            return name
    return ""


@check("def_rtp", "defender", 5, refs=("MS: Microsoft Defender Antivirus",))
def def_rtp(f):
    mp = f.psv("mp")
    if isinstance(mp, dict) and mp.get("AMRunningMode") == "Normal" and is_true(mp.get("AntivirusEnabled")) \
            and is_true(mp.get("RealTimeProtectionEnabled")):
        return R("pass", t("audit.def_rtp.on"))
    other = other_av(f)
    if other:
        return R("pass", t("audit.def_rtp.other", name=other))
    if mp is None:
        return R("fail", t("audit.def_rtp.unreadable"))
    return R("fail", t("audit.def_rtp.off", mode=mp.get("AMRunningMode") or "?"))


@check("def_sigs", "defender", 3, refs=("MS: Defender security intelligence updates",))
def def_sigs(f):
    mp = f.psv("mp")
    if not isinstance(mp, dict) or mp.get("AntivirusSignatureAge") is None:
        return R("info", t("audit.def_na")) if other_av(f) else R("unknown", t("audit.cant_read"))
    age = int(mp["AntivirusSignatureAge"])
    status = "pass" if age <= 3 else "warn" if age <= 7 else "fail"
    return R(status, t("audit.def_sigs.age", n=age))


@check("def_tamper", "defender", 3, refs=("MS: Tamper protection", "ATT&CK T1562.001"))
def def_tamper(f):
    mp = f.psv("mp")
    if not isinstance(mp, dict):
        return R("info", t("audit.def_na")) if other_av(f) else R("unknown", t("audit.cant_read"))
    return R("pass", t("audit.on")) if is_true(mp.get("IsTamperProtected")) else R("fail", t("audit.off"))


def classify_exclusions(paths, procs, exts) -> tuple:
    """(suspicious, all) as "type: value" strings."""
    sus, every = [], []
    for p in paths:
        every.append(f"path: {p}")
        if SUSP_PATH.search(p):
            sus.append(f"path: {p}")
    for p in procs:
        every.append(f"process: {p}")
        if SUSP_PROC.search(p.strip()):
            sus.append(f"process: {p}")
    for e in exts:
        every.append(f"ext: {e}")
        if e.strip().lstrip("*.").lower() in SUSP_EXT:
            sus.append(f"ext: {e}")
    return sus, every


@check("def_excl", "defender", 4, refs=("ATT&CK T1562.001",), harden="def.review_exclusions")
def def_excl(f):
    pref = f.psv("mppref")
    if not isinstance(pref, dict):
        return R("info", t("audit.def_na")) if other_av(f) else R("unknown", t("audit.cant_read"))
    lists = [[str(x) for x in as_list(pref.get(k)) if x] for k in ("ExclusionPath", "ExclusionProcess",
                                                                    "ExclusionExtension")]
    if any(ADMIN_NA in x.lower() for lst in lists for x in lst):
        return R("unknown", t("audit.need_admin"), admin=True)
    sus, every = classify_exclusions(*lists)
    if sus:
        return R("fail", t("audit.def_excl.suspicious", n=len(sus)), items=sus + [x for x in every if x not in sus])
    if every:
        return R("warn", t("audit.def_excl.some", n=len(every)), items=every)
    return R("pass", t("audit.def_excl.none"))


@check("def_asr", "defender", 2, refs=("MS: Attack surface reduction rules",), harden="def.asr")
def def_asr(f):
    pref = f.psv("mppref")
    if not isinstance(pref, dict):
        return R("info", t("audit.def_na")) if other_av(f) else R("unknown", t("audit.cant_read"))
    ids = [x for x in as_list(pref.get("AsrIds")) if x]
    acts = [x for x in as_list(pref.get("AsrActions")) if x is not None]
    block = sum(1 for a in acts if int(a) in (1, 6))
    audit = sum(1 for a in acts if int(a) == 2)
    if not ids:
        return R("warn", t("audit.def_asr.none"))
    return R("pass" if block >= 5 else "warn", t("audit.def_asr.count", block=block, audit=audit))


@check("def_pua", "defender", 1, refs=("MS: PUA protection",), harden="def.pua")
def def_pua(f):
    pref = f.psv("mppref")
    if not isinstance(pref, dict):
        return R("info", t("audit.def_na")) if other_av(f) else R("unknown", t("audit.cant_read"))
    v = int(pref.get("PUAProtection") or 0)
    return R("pass", t("audit.on")) if v == 1 else R("warn", t("audit.def_pua.audit" if v == 2 else "audit.off"))
