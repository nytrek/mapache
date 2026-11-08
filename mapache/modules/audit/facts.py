"""Data collection for the audit (read-only).

Registry values come from winreg. Everything else comes from a single PowerShell call returning JSON,
with one try/catch per section. Tests build Facts with fake data.
"""
import ctypes
import json
import os
import re

from ...core.fs import exists, lp
from ...core.proc import powershell
from ...core.winreg_util import CIDict, reg_subkeys, reg_values, winreg

PS_BUNDLE = r"""
$r = [ordered]@{}
function T($n, $sb) { try { $v = & $sb; $r[$n] = $v } catch { $r[$n] = @{ __error = $_.Exception.Message } } }
T 'mp' { Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, AntivirusEnabled,
    RealTimeProtectionEnabled, BehaviorMonitorEnabled, AntivirusSignatureAge, IsTamperProtected,
    @{n='AMRunningMode';e={[string]$_.AMRunningMode}} }
T 'mppref' { $p = Get-MpPreference -ErrorAction Stop; [ordered]@{
    ExclusionPath = @($p.ExclusionPath); ExclusionProcess = @($p.ExclusionProcess);
    ExclusionExtension = @($p.ExclusionExtension); AsrIds = @($p.AttackSurfaceReductionRules_Ids);
    AsrActions = @($p.AttackSurfaceReductionRules_Actions); PUAProtection = [int]$p.PUAProtection } }
T 'av' { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
    Select-Object displayName, productState) }
T 'fw' { @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,
    @{n='Enabled';e={[string]$_.Enabled}}, @{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}}) }
T 'smb' { Get-SmbServerConfiguration -ErrorAction Stop | Select-Object EnableSMB1Protocol, RequireSecuritySignature }
T 'bl' { Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop | Select-Object
    @{n='ProtectionStatus';e={[string]$_.ProtectionStatus}}, @{n='VolumeStatus';e={[string]$_.VolumeStatus}},
    EncryptionPercentage, @{n='Protectors';e={@($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })}} }
T 'blshell' { (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection') }
T 'dg' { Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop |
    Select-Object VirtualizationBasedSecurityStatus, @{n='Running';e={@($_.SecurityServicesRunning)}},
    @{n='Configured';e={@($_.SecurityServicesConfigured)}} }
T 'tpm' { @(Get-PnpDevice -Class SecurityDevices -PresentOnly -ErrorAction Stop | Select-Object FriendlyName, Status) }
T 'admins' { @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Select-Object Name,
    @{n='Class';e={[string]$_.ObjectClass}}) }
T 'users' { @(Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, @{n='Sid';e={$_.SID.Value}}) }
T 'me' { "$env:USERDOMAIN\$env:USERNAME" }
T 'hotfix' { Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | Sort-Object InstalledOn -Descending |
    Select-Object -First 1 HotFixID, @{n='On';e={$_.InstalledOn.ToString('yyyy-MM-dd')}} }
T 'wmi' { @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop |
    Select-Object Name, @{n='Class';e={$_.CimClass.CimClassName}}, CommandLineTemplate, ScriptText, ScriptFileName) }
T 'tasks' { @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
    $t = $_; foreach ($a in $t.Actions) { [pscustomobject]@{ Path = $t.TaskPath + $t.TaskName;
    Exe = [string]$a.Execute; Args = [string]$a.Arguments } } }) }
T 'rootcerts' { $u = @(Get-ChildItem 'HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates' -ErrorAction Stop |
    ForEach-Object PSChildName); @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $u -contains $_.Thumbprint } |
    Select-Object Subject, Thumbprint, @{n='NotAfter';e={$_.NotAfter.ToString('yyyy-MM-dd')}}) }
if ($env:MAPACHE_ADMIN -eq '1') {
    T 'features' { @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.FeatureName -in
        @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2', 'SMB1Protocol') } |
        Select-Object FeatureName, @{n='State';e={[string]$_.State}}) }
}
$r | ConvertTo-Json -Depth 6 -Compress
"""
# indented lines continue the previous one (-Command needs a single line)
PS_BUNDLE = re.sub(r"\n[ ]{4,}", " ", PS_BUNDLE)

SIG_PS = (r"$ps = $env:MAPACHE_PATHS | ConvertFrom-Json; @(foreach ($p in $ps) { "
          r"$s = Get-AuthenticodeSignature -LiteralPath $p; [pscustomobject]@{ Path = $p; "
          r"Status = [string]$s.Status; Signer = [string]$s.SignerCertificate.Subject } }) | ConvertTo-Json -Compress")

HIVES = {}
if winreg is not None:
    HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}


def as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


class Facts:
    """System facts. `reg`, `ps` and `files` allow injecting fake data in tests."""

    def __init__(self, admin: bool, ps: dict = None, reg: dict = None, files: dict = None, sigs: dict = None,
                 dma=None):
        self.admin = admin
        self.ps = ps if ps is not None else {}
        self._reg = reg
        self._files = files  # {path: content}, tests only
        self.sigs = sigs if sigs is not None else {}  # ikey(path) -> (status, signer)
        self._dma = dma

    # --- Collection ---
    def collect(self):
        try:
            r = powershell(PS_BUNDLE, env={"MAPACHE_ADMIN": "1" if self.admin else "0"}, timeout=240)
            out = r.stdout.strip()
            self.ps = json.loads(out[out.find("{"):]) if "{" in out else {}
        except (OSError, ValueError) as e:
            self.ps = {"__error": str(e)}
        return self

    def check_signatures(self, paths):
        """Authenticode status for a bounded set of executables (one PowerShell call)."""
        from ...core.fs import ikey
        todo = sorted({p for p in paths if p and ikey(p) not in self.sigs and exists(p)})[:300]
        if not todo or self._reg is not None:
            return
        try:
            r = powershell(SIG_PS, env={"MAPACHE_PATHS": json.dumps(todo)}, timeout=300)
            data = json.loads(r.stdout.strip() or "[]")
        except (OSError, ValueError):
            return
        for d in as_list(data):
            self.sigs[ikey(d.get("Path", ""))] = (d.get("Status") or "", d.get("Signer") or "")

    # --- Access ---
    def psv(self, key):
        """PowerShell section data, or None if it failed."""
        v = self.ps.get(key)
        if isinstance(v, dict) and "__error" in v:
            return None
        return v

    def ps_error(self, key) -> str:
        v = self.ps.get(key)
        return v.get("__error", "") if isinstance(v, dict) else ("" if key in self.ps else "missing")

    def values(self, path: str, hive: str = "HKLM", view: int = 0) -> dict:
        if self._reg is not None:
            return CIDict(self._reg.get(f"{hive}\\{path}", {}))
        h = HIVES.get(hive)
        return reg_values(h, path, view) if h is not None else {}

    def val(self, path: str, name: str, hive: str = "HKLM", default=None, view: int = 0):
        return self.values(path, hive, view).get(name, default)

    def subkeys(self, path: str, hive: str = "HKLM", view: int = 0) -> list:
        if self._reg is not None:
            pre = f"{hive}\\{path}\\".lower()
            return sorted({k[len(pre):].split("\\")[0] for k in self._reg if k.lower().startswith(pre)})
        h = HIVES.get(hive)
        return reg_subkeys(h, path, view) if h is not None else []

    def has_key(self, path: str, hive: str = "HKLM") -> bool:
        if self._reg is not None:
            k = f"{hive}\\{path}".lower()
            return any(x.lower() == k or x.lower().startswith(k + "\\") for x in self._reg)
        h = HIVES.get(hive)
        if h is None:
            return False
        try:
            with winreg.OpenKey(h, path, 0, winreg.KEY_READ):
                return True
        except OSError:
            return False

    def read_text(self, path) -> str:
        if self._files is not None:
            return self._files.get(str(path), "")
        try:
            with open(lp(path), encoding="utf-8", errors="replace") as f:
                return f.read(2 * 1024 * 1024)
        except OSError:
            return ""

    def dma_protection(self):
        """Kernel DMA protection via NtQuerySystemInformation(202). None if unavailable."""
        if self._dma is not None or self._reg is not None:
            return self._dma
        try:
            buf = ctypes.c_ubyte(0)
            ret = ctypes.c_ulong(0)
            st = ctypes.WinDLL("ntdll").NtQuerySystemInformation(202, ctypes.byref(buf), 1, ctypes.byref(ret))
            return bool(buf.value) if st == 0 else None
        except (AttributeError, OSError):
            return None

    def signature(self, path):
        from ...core.fs import ikey
        return self.sigs.get(ikey(path))


# --- Helpers for checks ---

def expand(p: str) -> str:
    return os.path.expandvars((p or "").strip().strip('"'))


def is_true(v) -> bool:
    return v is True or str(v).lower() in ("true", "1")


def norm_cmd(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())
