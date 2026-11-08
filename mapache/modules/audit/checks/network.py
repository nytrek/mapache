"""Network: firewall, SMBv1, SMB signing, LLMNR, NetBIOS, RDP and Remote Registry."""
from ....i18n import t
from ..facts import as_list, is_true
from . import R, check

SVC = r"SYSTEM\CurrentControlSet\Services"


@check("fw", "network", 5, refs=("MS: Windows Firewall",), harden="net.firewall")
def fw(f):
    profs = f.psv("fw")
    if profs is None:
        return R("unknown", t("audit.cant_read"))
    off = [p.get("Name") for p in as_list(profs) if not is_true(p.get("Enabled"))]
    allow = [p.get("Name") for p in as_list(profs) if str(p.get("DefaultInboundAction")) == "Allow"]
    if off:
        return R("fail", t("audit.fw.off", profiles=", ".join(map(str, off))))
    if allow:
        return R("warn", t("audit.fw.allow", profiles=", ".join(map(str, allow))))
    return R("pass", t("audit.fw.ok"))


@check("smb1", "network", 4, refs=("MS17-010 (EternalBlue)", "ATT&CK T1210"), harden="net.smb1_off")
def smb1(f):
    feats = {d.get("FeatureName"): d.get("State") for d in as_list(f.psv("features"))}
    if "SMB1Protocol" in feats:
        return R("fail", t("audit.smb1.on")) if feats["SMB1Protocol"] == "Enabled" else R("pass", t("audit.off"))
    smb = f.psv("smb")
    client = f.val(rf"{SVC}\mrxsmb10", "Start")
    server_on = is_true(smb.get("EnableSMB1Protocol")) if isinstance(smb, dict) else \
        f.val(rf"{SVC}\LanmanServer\Parameters", "SMB1") not in (0, None)
    if server_on or client in (1, 2, 3):
        return R("fail", t("audit.smb1.on"))
    if smb is None and client is None:
        return R("unknown", t("audit.cant_read"))
    return R("pass", t("audit.off"))


@check("smb_sign", "network", 2, refs=("MS: SMB signing", "ATT&CK T1557.001"), harden="net.smb_signing")
def smb_sign(f):
    srv = f.val(rf"{SVC}\LanmanServer\Parameters", "RequireSecuritySignature")
    cli = f.val(rf"{SVC}\LanmanWorkstation\Parameters", "RequireSecuritySignature")
    if srv == 1 and cli == 1:
        return R("pass", t("audit.smb_sign.both"))
    missing = [x for x, v in (("server", srv), ("client", cli)) if v != 1]
    return R("warn", t("audit.smb_sign.missing", which=", ".join(missing)))


@check("llmnr", "network", 3, refs=("ATT&CK T1557.001",), harden="net.llmnr_off")
def llmnr(f):
    v = f.val(r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast")
    return R("pass", t("audit.off")) if v == 0 else R("fail", t("audit.llmnr.on"))


@check("netbios", "network", 2, refs=("ATT&CK T1557.001",), harden="net.netbios_off")
def netbios(f):
    base = rf"{SVC}\NetBT\Parameters\Interfaces"
    ifs = [i for i in f.subkeys(base) if i.lower().startswith("tcpip_")]
    if not ifs:
        return R("unknown", t("audit.cant_read"))
    on = [i for i in ifs if f.val(rf"{base}\{i}", "NetbiosOptions") != 2]
    if not on:
        return R("pass", t("audit.off"))
    return R("warn", t("audit.netbios.on", n=len(on), m=len(ifs)))


@check("rdp", "network", 3, refs=("ATT&CK T1021.001",), harden="net.rdp_off")
def rdp(f):
    deny = f.val(r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    if deny in (1, None):
        return R("pass", t("audit.off"))
    nla = f.val(r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
    return R("warn", t("audit.rdp.nla")) if nla == 1 else R("fail", t("audit.rdp.no_nla"))


@check("remotereg", "network", 2, refs=("ATT&CK T1112",), harden="net.remotereg_off")
def remotereg(f):
    start = f.val(rf"{SVC}\RemoteRegistry", "Start")
    if start is None or start == 4:
        return R("pass", t("audit.off"))
    if start == 3:
        return R("pass", t("audit.remotereg.manual"))
    return R("fail", t("audit.remotereg.auto"))
