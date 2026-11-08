"""Privacy rules as data.

Only documented policies and settings. Browsers are configured through enterprise policies under
HKLM\\SOFTWARE\\Policies, which makes them show "Managed by your organization".
"""
import os

from ...core.winreg_util import reg_values, winreg
from ..harden.engine import RegValue
from ..harden.rules import Rule

LEVELS = ["basic", "advanced"]
POL = r"SOFTWARE\Policies\Microsoft\Windows"
CDM = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
ADV = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
DOH_URL = "https://dns.quad9.net/dns-query"  # Quad9: non-profit, no IP logging, blocks malicious domains

# policy key per Chromium browser
CHROMIUM = {"chrome": r"SOFTWARE\Policies\Google\Chrome",
            "edge": r"SOFTWARE\Policies\Microsoft\Edge",
            "brave": r"SOFTWARE\Policies\BraveSoftware\Brave"}
FIREFOX = r"SOFTWARE\Policies\Mozilla\Firefox"
EXES = {"chrome": "chrome.exe", "edge": "msedge.exe", "brave": "brave.exe", "firefox": "firefox.exe"}


def _hk(name):
    return getattr(winreg, name) if winreg else None


def _cur_version() -> dict:
    return reg_values(_hk("HKEY_LOCAL_MACHINE"), r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") if winreg else {}


def enterprise() -> bool:
    """AllowTelemetry=0 is only honored on Enterprise, Education and Server; elsewhere the minimum is 1."""
    ed = str(_cur_version().get("EditionID", "")).lower()
    return ed.startswith(("enterprise", "education", "server", "iot"))


def build() -> int:
    try:
        return int(_cur_version().get("CurrentBuildNumber", 0))
    except ValueError:
        return 0


def installed(b: str) -> bool:
    """True if the browser has an App Paths entry whose executable exists."""
    if winreg is None:
        return False
    key = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{EXES[b]}"
    for h in ("HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"):
        try:
            with winreg.OpenKey(_hk(h), key) as k:
                exe = os.path.expandvars(str(winreg.QueryValueEx(k, "")[0]).strip().strip('"'))
        except OSError:
            continue
        if exe and os.path.isfile(exe):
            return True
    return False


def browsers() -> list:
    return [b for b in EXES if installed(b)]


def _chromium(values, only=None):
    """[(name, type, value)] -> actions for each installed Chromium browser (optionally only `only`)."""
    out = []
    for b in browsers():
        if b in CHROMIUM and (only is None or b in only):
            out += [RegValue("HKLM", CHROMIUM[b], n, typ, v) for n, typ, v in values]
    return out


def _firefox(values, sub=""):
    if "firefox" not in browsers():
        return []
    path = FIREFOX + (f"\\{sub}" if sub else "")
    return [RegValue("HKLM", path, n, typ, v) for n, typ, v in values]


D = "REG_DWORD"

# --- Browsers ---

def web_telemetry():
    # Chrome ignores MetricsReportingEnabled outside an Active Directory domain; Brave honors it.
    return (_chromium([("MetricsReportingEnabled", D, 0)], only=("brave",))
            # Edge on Windows 10/11 follows the Windows diagnostic level
            + _chromium([("DiagnosticData", D, 0), ("UserFeedbackAllowed", D, 0)], only=("edge",))
            + _chromium([("BraveP3AEnabled", D, 0), ("BraveStatsPingEnabled", D, 0),
                         ("BraveWebDiscoveryEnabled", D, 0)], only=("brave",))
            + _firefox([("DisableTelemetry", D, 1), ("DisableFirefoxStudies", D, 1)]))


def web_ads():
    # Chrome PrivacySandbox* policies are deprecated
    return (_chromium([("PersonalizationReportingEnabled", D, 0), ("ShowMicrosoftRewards", D, 0),
                         ("EdgeShoppingAssistantEnabled", D, 0), ("ShowRecommendationsEnabled", D, 0),
                         ("SpotlightExperiencesAndRecommendationsEnabled", D, 0)], only=("edge",))
            + _firefox([("SponsoredTopSites", D, 0), ("SponsoredPocket", D, 0)], sub="FirefoxHome"))


def web_cookies():
    # Firefox partitions third-party cookies by default
    return _chromium([("BlockThirdPartyCookies", D, 1)], only=("chrome", "edge", "brave"))


def web_webrtc():
    # WebRtcIPHandling on Chrome/Brave, WebRtcLocalhostIpHandling on Edge
    v = "default_public_interface_only"
    return (_chromium([("WebRtcIPHandling", "REG_SZ", v)], only=("chrome", "brave"))
            + _chromium([("WebRtcLocalhostIpHandling", "REG_SZ", v)], only=("edge",)))


def web_doh():
    return (_chromium([("DnsOverHttpsMode", "REG_SZ", "secure"), ("DnsOverHttpsTemplates", "REG_SZ", DOH_URL)])
            + _firefox([("Enabled", D, 1), ("ProviderURL", "REG_SZ", DOH_URL)], sub="DNSOverHTTPS"))


def web_suggest():
    return (_chromium([("SearchSuggestEnabled", D, 0)])
            + _firefox([("SearchSuggestEnabled", D, 0)]))


def _has(fn):
    return lambda: bool(fn())


RULES = [
    # --- Basic ---
    Rule("win.telemetry", "basic", "low", lambda: [
        RegValue("HKLM", rf"{POL}\DataCollection", "AllowTelemetry", D, 0 if enterprise() else 1, accept=[0]),
        RegValue("HKLM", rf"{POL}\DataCollection", "DoNotShowFeedbackNotifications", D, 1),
        RegValue("HKCU", r"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", D, 0)],
        refs=("MS: Configure Windows diagnostic data",)),
    Rule("win.adid", "basic", "low", lambda: [
        RegValue("HKLM", rf"{POL}\AdvertisingInfo", "DisabledByGroupPolicy", D, 1),
        RegValue("HKCU", r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", D, 0)],
        refs=("MS: Advertising ID",)),
    Rule("win.activity", "basic", "low", lambda: [
        RegValue("HKLM", rf"{POL}\System", n, D, 0)
        for n in ("EnableActivityFeed", "PublishUserActivities", "UploadUserActivities")],
        refs=("MS: Activity history",)),
    Rule("win.tailored", "basic", "low", lambda: [
        RegValue("HKCU", r"Software\Policies\Microsoft\Windows\CloudContent",
                 "DisableTailoredExperiencesWithDiagnosticData", D, 1),
        RegValue("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Privacy",
                 "TailoredExperiencesWithDiagnosticDataEnabled", D, 0)], refs=("MS: Tailored experiences",)),
    Rule("win.start_ads", "basic", "low", lambda: [
        *[RegValue("HKCU", CDM, n, D, 0) for n in (
            "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-353694Enabled",
            "SubscribedContent-353696Enabled", "SystemPaneSuggestionsEnabled", "SilentInstalledAppsEnabled",
            "SoftLandingEnabled")],
        RegValue("HKCU", ADV, "Start_IrisRecommendations", D, 0),
        RegValue("HKCU", ADV, "ShowSyncProviderNotifications", D, 0)], refs=("Settings > Personalization",)),
    Rule("win.lock_ads", "basic", "low", lambda: [
        RegValue("HKCU", CDM, "RotatingLockScreenOverlayEnabled", D, 0),
        RegValue("HKCU", CDM, "SubscribedContent-338387Enabled", D, 0)], refs=("Settings > Lock screen",)),
    Rule("win.websearch", "basic", "low", lambda: [
        RegValue("HKCU", r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", D, 1),
        RegValue("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", D, 0)],
        refs=("MS: DisableSearchBoxSuggestions",)),
    Rule("win.typing", "basic", "low", lambda: [
        RegValue("HKCU", r"Software\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", D, 1),
        RegValue("HKCU", r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", D, 1),
        RegValue("HKCU", r"Software\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", D, 0),
        RegValue("HKCU", r"Software\Microsoft\Personalization\Settings", "AcceptedPrivacyPolicy", D, 0)],
        refs=("Settings > Inking & typing personalization",)),
    # Recall exists from build 26100, on Copilot+ PCs only
    Rule("win.recall", "basic", "low", lambda: [
        RegValue("HKLM", rf"{POL}\WindowsAI", "DisableAIDataAnalysis", D, 1),
        RegValue("HKCU", r"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", D, 1)],
        available=lambda: build() >= 26100, refs=("MS: DisableAIDataAnalysis (Recall)",)),
    Rule("web.telemetry", "basic", "low", web_telemetry, available=_has(web_telemetry),
         refs=("Chrome/Edge/Brave/Firefox enterprise policies",)),
    Rule("web.ads", "basic", "low", web_ads, available=_has(web_ads),
         refs=("Chrome Privacy Sandbox policies", "Edge policies", "Firefox FirefoxHome policy")),
    Rule("web.webrtc", "basic", "low", web_webrtc, available=_has(web_webrtc), refs=("WebRtcIPHandlingPolicy",)),

    # --- Advanced ---
    Rule("web.cookies", "advanced", "low", web_cookies, available=_has(web_cookies), refs=("BlockThirdPartyCookies",)),
    Rule("web.doh", "advanced", "medium", web_doh, available=_has(web_doh), refs=("DnsOverHttpsMode", "Quad9")),
    Rule("web.suggest", "advanced", "low", web_suggest, available=_has(web_suggest), refs=("SearchSuggestEnabled",)),
    Rule("win.location", "advanced", "medium", lambda: [
        RegValue("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
                 "Value", "REG_SZ", "Deny")], refs=("Settings > Privacy > Location",)),
    Rule("win.clipboard", "advanced", "low", lambda: [
        RegValue("HKLM", rf"{POL}\System", "AllowCrossDeviceClipboard", D, 0)], refs=("MS: AllowCrossDeviceClipboard",)),
]

BY_ID = {r.id: r for r in RULES}

# explained, not automated
GUIDES = ["fingerprint", "browsers", "edition", "permissions", "account", "services"]
