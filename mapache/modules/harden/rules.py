"""Hardening rules as data.

Each rule has an id (matching the audit `harden` field), level, risk, actions, reboot flag, availability
and references. Visible texts live in the locales: harden.<id>.title / .desc / .breaks
"""
from dataclasses import dataclass, field

from ...core.winreg_util import reg_subkeys, reg_values, winreg
from .engine import AsrRule, Feature, FirewallOn, HibernateOff, MpPref, RegValue

LEVELS = ["basic", "advanced", "paranoid"]
SVC = r"SYSTEM\CurrentControlSet\Services"
POL_SYS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


@dataclass
class Rule:
    id: str
    level: str
    risk: str
    actions: object  # () -> list[Action], evaluated lazily
    reboot: bool = False
    available: object = None  # () -> bool
    refs: tuple = field(default_factory=tuple)
    title: str = ""  # dynamic rules: literal title
    note: str = ""  # dynamic rules: literal detail

    def build(self) -> list:
        return self.actions()

    def is_available(self) -> bool:
        return self.available() if self.available else True


def _netbios_actions():
    base = rf"{SVC}\NetBT\Parameters\Interfaces"
    hk = winreg.HKEY_LOCAL_MACHINE if winreg else None
    ifs = [i for i in reg_subkeys(hk, base) if i.lower().startswith("tcpip_")] if hk else []
    return [RegValue("HKLM", rf"{base}\{i}", "NetbiosOptions", "REG_DWORD", 2) for i in ifs]


def _not_home() -> bool:
    if winreg is None:
        return False
    ed = str(reg_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").get("EditionID", ""))
    return not ed.lower().startswith("core")


def _has_office() -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Office\16.0"):
            return True
    except OSError:
        return False


# Microsoft ASR rules. Excluded on purpose: executable prevalence (01443614-...) and
# PSExec/WMI process creation (d1e49aac-...), which break admin and development tools.
ASR = {
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "email_exec",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "office_child",
    "3b576869-a4ec-4529-8536-b80a7769e899": "office_exec",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "office_inject",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "script_download",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "obfuscated",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "macro_win32",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "lsass",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "usb",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "ransomware",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "wmi",
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "drivers",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "adobe",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "office_comm",
}

RULES = [
    # --- Basic ---
    Rule("net.llmnr_off", "basic", "low", lambda: [
        RegValue("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", "REG_DWORD", 0)],
        refs=("ATT&CK T1557.001",)),
    Rule("net.netbios_off", "basic", "low", _netbios_actions, refs=("ATT&CK T1557.001",)),
    Rule("net.firewall", "basic", "low", lambda: [FirewallOn()], refs=("MS: Windows Firewall",)),
    Rule("net.smb1_off", "basic", "low", lambda: [Feature("SMB1Protocol", False)], reboot=True,
         refs=("MS17-010",)),
    Rule("net.remotereg_off", "basic", "low", lambda: [
        RegValue("HKLM", rf"{SVC}\RemoteRegistry", "Start", "REG_DWORD", 4)], refs=("ATT&CK T1112",)),
    Rule("net.rdp_off", "basic", "low", lambda: [
        RegValue("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", "REG_DWORD", 1)],
        refs=("ATT&CK T1021.001",)),
    Rule("iso.wdigest_off", "basic", "low", lambda: [
        RegValue("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential",
                 "REG_DWORD", 0, default=0)], refs=("ATT&CK T1003.001",)),
    Rule("sys.smartscreen", "basic", "low", lambda: [
        RegValue("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", "REG_DWORD", 1),
        RegValue("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "ShellSmartScreenLevel", "REG_SZ", "Warn")],
        refs=("MS: SmartScreen",)),
    Rule("sys.uac_max", "basic", "low", lambda: [
        RegValue("HKLM", POL_SYS, "EnableLUA", "REG_DWORD", 1),
        RegValue("HKLM", POL_SYS, "ConsentPromptBehaviorAdmin", "REG_DWORD", 2),
        RegValue("HKLM", POL_SYS, "PromptOnSecureDesktop", "REG_DWORD", 1)], refs=("MS: UAC",)),
    Rule("sys.autorun_off", "basic", "low", lambda: [
        RegValue("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun",
                 "REG_DWORD", 255)], refs=("ATT&CK T1091",)),
    Rule("sys.pslog", "basic", "low", lambda: [
        RegValue("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                 "EnableScriptBlockLogging", "REG_DWORD", 1)], refs=("ATT&CK T1059.001",)),
    Rule("sys.psv2_off", "basic", "low", lambda: [Feature("MicrosoftWindowsPowerShellV2Root", False)],
         refs=("ATT&CK T1059.001",)),
    Rule("sys.lock", "basic", "low", lambda: [RegValue("HKLM", POL_SYS, "InactivityTimeoutSecs", "REG_DWORD", 900)],
         refs=("MS: Machine inactivity limit",)),
    Rule("sys.office_macros", "basic", "low", lambda: [
        RegValue("HKCU", rf"Software\Policies\Microsoft\Office\16.0\{app}\Security",
                 "blockcontentexecutionfrominternet", "REG_DWORD", 1) for app in ("Word", "Excel", "PowerPoint")],
        available=_has_office, refs=("ATT&CK T1204.002",)),
    Rule("def.pua", "basic", "low", lambda: [MpPref("PUAProtection", 1)], refs=("MS: PUA protection",)),
    Rule("def.asr", "basic", "low", lambda: [AsrRule(g, 2) for g in ASR], refs=("MS: ASR rules (audit mode)",)),
    Rule("mem.small_dumps", "basic", "low", lambda: [
        RegValue("HKLM", r"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled", "REG_DWORD", 3)],
        refs=("MS: Memory dump options",)),

    # --- Advanced ---
    Rule("net.smb_signing", "advanced", "medium", lambda: [
        RegValue("HKLM", rf"{SVC}\LanmanServer\Parameters", "RequireSecuritySignature", "REG_DWORD", 1),
        RegValue("HKLM", rf"{SVC}\LanmanWorkstation\Parameters", "RequireSecuritySignature", "REG_DWORD", 1)],
        reboot=True, refs=("ATT&CK T1557.001",)),
    Rule("iso.lsa_ppl", "advanced", "medium", lambda: [
        RegValue("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", "REG_DWORD", 1)], reboot=True,
        refs=("ATT&CK T1003.001",)),
    Rule("def.asr_block", "advanced", "medium", lambda: [AsrRule(g, 1) for g in ASR], refs=("MS: ASR rules",)),
    Rule("mem.clear_pagefile", "advanced", "low", lambda: [
        RegValue("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                 "ClearPageFileAtShutdown", "REG_DWORD", 1)], reboot=True, refs=("MS: Clear pagefile",)),
    Rule("mem.hiber", "advanced", "low", lambda: [HibernateOff()], refs=("ATT&CK T1003",)),
    Rule("iso.hvci", "advanced", "high", lambda: [
        RegValue("HKLM", r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                 "Enabled", "REG_DWORD", 1)], reboot=True, refs=("MS: Memory integrity",)),

    # --- Paranoid ---
    Rule("iso.credguard", "paranoid", "high", lambda: [
        RegValue("HKLM", r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity",
                 "REG_DWORD", 1),
        RegValue("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags", "REG_DWORD", 1)], reboot=True,
        available=_not_home, refs=("ATT&CK T1003.001",)),
    Rule("sys.wsh_off", "paranoid", "medium", lambda: [
        RegValue("HKLM", r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", "REG_DWORD", 0)],
        refs=("ATT&CK T1059.005",)),
]

BY_ID = {r.id: r for r in RULES}
# audit ids fixed by different rule ids
AUDIT_ALIASES = {}

# steps that should not be automated
GUIDES = ["bitlocker", "secureboot", "wu", "defender_exclusions", "standard_account"]
