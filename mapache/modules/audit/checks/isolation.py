"""Isolation and credentials: VBS/HVCI, Credential Guard, LSA protection and WDigest."""
from ....i18n import t
from ..facts import as_list
from . import R, check

LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
WDIGEST = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
CURRENT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def _dg(f):
    dg = f.psv("dg")
    if not isinstance(dg, dict):
        return None
    return dict(vbs=int(dg.get("VirtualizationBasedSecurityStatus") or 0),
                running={int(x) for x in as_list(dg.get("Running")) if x is not None})


def is_home(f) -> bool:
    return str(f.val(CURRENT, "EditionID", default="")).lower().startswith("core")


@check("vbs", "isolation", 2, refs=("MS: Memory integrity (HVCI)",), harden="iso.hvci")
def vbs(f):
    d = _dg(f)
    if d is None:
        return R("unknown", t("audit.cant_read"))
    if d["vbs"] == 2 and 2 in d["running"]:
        return R("pass", t("audit.vbs.hvci_on"))
    if d["vbs"] == 2:
        return R("warn", t("audit.vbs.vbs_only"))
    return R("warn", t("audit.vbs.off"))


@check("credguard", "isolation", 2, refs=("MS: Credential Guard", "ATT&CK T1003.001"), harden="iso.credguard")
def credguard(f):
    if is_home(f):
        return R("info", t("audit.credguard.home"))
    d = _dg(f)
    if d is None:
        return R("unknown", t("audit.cant_read"))
    return R("pass", t("audit.on")) if 1 in d["running"] else R("warn", t("audit.off"))


@check("lsa_ppl", "isolation", 3, refs=("MS: LSA protection", "ATT&CK T1003.001"), harden="iso.lsa_ppl")
def lsa_ppl(f):
    v = f.val(LSA, "RunAsPPL")
    if v in (1, 2) or f.val(LSA, "RunAsPPLBoot") in (1, 2):
        return R("pass", t("audit.on"))
    return R("warn", t("audit.off"))


@check("wdigest", "isolation", 4, refs=("MS KB2871997", "ATT&CK T1003.001"), harden="iso.wdigest_off")
def wdigest(f):
    if f.val(WDIGEST, "UseLogonCredential") == 1:
        return R("fail", t("audit.wdigest.on"))
    return R("pass", t("audit.wdigest.off"))
