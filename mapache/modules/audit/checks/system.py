"""System: UAC, SmartScreen, PowerShell, Sysmon, Windows Update, AutoRun, accounts, lock screen, Office macros."""
import datetime as dt

from ....i18n import t
from ..facts import as_list, is_true
from . import R, check

POL_SYS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
POL_EXP = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
SVC = r"SYSTEM\CurrentControlSet\Services"


@check("uac", "system", 4, refs=("MS: User Account Control",), harden="sys.uac_max")
def uac(f):
    if f.val(POL_SYS, "EnableLUA") == 0:
        return R("fail", t("audit.uac.off"))
    cpba = f.val(POL_SYS, "ConsentPromptBehaviorAdmin", default=5)
    secure = f.val(POL_SYS, "PromptOnSecureDesktop", default=1)
    if cpba == 0:
        return R("fail", t("audit.uac.never"))
    if cpba in (1, 2) and secure == 1:
        return R("pass", t("audit.uac.always"))
    if secure != 1:
        return R("warn", t("audit.uac.no_secure_desktop"))
    return R("warn", t("audit.uac.default"))


@check("smartscreen", "system", 3, refs=("MS: Microsoft Defender SmartScreen",), harden="sys.smartscreen")
def smartscreen(f):
    pol = f.val(r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    exp = str(f.val(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", default="")).lower()
    if pol == 1:  # the policy overrides the user setting
        return R("pass", t("audit.on"))
    if pol == 0 or exp == "off":
        return R("fail", t("audit.off"))
    return R("pass", t("audit.on"))


@check("psv2", "system", 2, refs=("ATT&CK T1059.001", "Downgrade attack"), harden="sys.psv2_off")
def psv2(f):
    feats = {d.get("FeatureName"): d.get("State") for d in as_list(f.psv("features"))}
    if f.admin and f.psv("features") is not None:
        st = feats.get("MicrosoftWindowsPowerShellV2Root")
        if st == "Enabled":
            return R("fail", t("audit.psv2.on"))
        return R("pass", t("audit.psv2.removed" if st is None else "audit.off"))
    ver = str(f.val(r"SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine", "PowerShellVersion", default=""))
    if ver.startswith("2"):
        return R("unknown", t("audit.psv2.maybe"), admin=True)
    return R("pass", t("audit.psv2.removed"))


@check("pslog", "system", 1, refs=("MS: PowerShell script block logging", "ATT&CK T1059.001"), harden="sys.pslog")
def pslog(f):
    v = f.val(r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging")
    return R("pass", t("audit.on")) if v == 1 else R("warn", t("audit.off"))


@check("sysmon", "system", 0, refs=("Sysinternals Sysmon",))
def sysmon(f):
    for name in ("Sysmon64", "Sysmon"):
        if f.has_key(rf"{SVC}\{name}"):
            return R("info", t("audit.sysmon.on"))
    return R("info", t("audit.sysmon.off"))


@check("wu", "system", 4, refs=("MS: Windows Update",))
def wu(f):
    problems, worst = [], "pass"

    def bad(level, msg):
        nonlocal worst
        problems.append(msg)
        if level == "fail" or worst == "pass":
            worst = level

    if f.val(rf"{SVC}\wuauserv", "Start") == 4:
        bad("fail", t("audit.wu.service_off"))
    if f.val(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate") == 1:
        bad("warn", t("audit.wu.policy_off"))
    pause = f.val(r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", "PauseUpdatesExpiryTime")
    if pause:
        try:
            until = dt.datetime.fromisoformat(str(pause).rstrip("Z")[:19])
            if until > dt.datetime.now():
                bad("warn", t("audit.wu.paused", date=until.strftime("%Y-%m-%d")))
        except ValueError:
            pass
    hf = f.psv("hotfix")
    days = None
    if isinstance(hf, dict) and hf.get("On"):
        try:
            days = (dt.datetime.now() - dt.datetime.strptime(hf["On"], "%Y-%m-%d")).days
        except ValueError:
            pass
    if days is not None and days > 60:
        bad("fail", t("audit.wu.old", days=days, kb=hf.get("HotFixID", "")))
    elif days is not None and days > 35:
        bad("warn", t("audit.wu.old", days=days, kb=hf.get("HotFixID", "")))
    if problems:
        return R(worst, problems[0], items=problems[1:])
    if days is None:
        return R("unknown", t("audit.cant_read"))
    return R("pass", t("audit.wu.recent", days=days, kb=hf.get("HotFixID", "")))


@check("autorun", "system", 1, refs=("ATT&CK T1091",), harden="sys.autorun_off")
def autorun(f):
    for hive in ("HKLM", "HKCU"):
        if f.val(POL_EXP, "NoDriveTypeAutoRun", hive=hive) == 255 or f.val(POL_EXP, "NoAutorun", hive=hive) == 1:
            return R("pass", t("audit.off"))
    return R("warn", t("audit.autorun.default"))


@check("guest", "system", 3, refs=("MS: Guest account",))
def guest(f):
    users = f.psv("users")
    if users is None:
        return R("unknown", t("audit.cant_read"))
    g = [u for u in as_list(users) if str(u.get("Sid", "")).endswith("-501")]
    return R("fail", t("audit.on")) if g and is_true(g[0].get("Enabled")) else R("pass", t("audit.off"))


@check("admins", "system", 1, refs=("MS: Least privilege",))
def admins(f):
    members = f.psv("admins")
    users = f.psv("users")
    if members is None or users is None:
        return R("unknown", t("audit.cant_read"))
    enabled = {str(u.get("Name", "")).lower() for u in as_list(users) if is_true(u.get("Enabled"))}
    active = [str(m.get("Name")) for m in as_list(members) if m.get("Class") == "User"
              and str(m.get("Name", "")).split("\\")[-1].lower() in enabled]
    me = str(f.psv("me") or "").lower()
    daily_admin = any(a.lower() == me for a in active)
    if len(active) > 2:
        return R("warn", t("audit.admins.many", n=len(active)), items=active)
    if daily_admin:
        return R("warn", t("audit.admins.daily"), items=active)
    return R("pass", t("audit.admins.ok", n=len(active)), items=active)


@check("lock", "system", 1, refs=("MS: Interactive logon: machine inactivity limit",), harden="sys.lock")
def lock(f):
    secs = f.val(POL_SYS, "InactivityTimeoutSecs")
    if isinstance(secs, int) and 0 < secs <= 900:
        return R("pass", t("audit.lock.policy", min=secs // 60 or 1))
    d = f.values(r"Control Panel\Desktop", hive="HKCU")
    try:
        timeout = int(d.get("ScreenSaveTimeOut", 0))
    except ValueError:
        timeout = 0
    if str(d.get("ScreenSaveActive")) == "1" and str(d.get("ScreenSaverIsSecure")) == "1" and 0 < timeout <= 900:
        return R("pass", t("audit.lock.saver", min=timeout // 60 or 1))
    return R("warn", t("audit.lock.none"))


@check("office_macros", "system", 2, refs=("MS: Macros from the internet blocked", "ATT&CK T1204.002"),
       harden="sys.office_macros")
def office_macros(f):
    if not f.has_key(r"Software\Microsoft\Office\16.0", hive="HKCU"):
        return R("info", t("audit.office.none"))
    bad, weak = [], []
    for app in ("Word", "Excel", "PowerPoint"):
        for base in (r"Software\Microsoft\Office\16.0", r"Software\Policies\Microsoft\Office\16.0"):
            sec = f.values(rf"{base}\{app}\Security", hive="HKCU")
            if sec.get("VBAWarnings") == 1:
                bad.append(app)
            if sec.get("blockcontentexecutionfrominternet") == 0:
                weak.append(app)
    if bad:
        return R("fail", t("audit.office.all_enabled", apps=", ".join(sorted(set(bad)))))
    if weak:
        return R("warn", t("audit.office.internet", apps=", ".join(sorted(set(weak)))))
    return R("pass", t("audit.office.ok"))
