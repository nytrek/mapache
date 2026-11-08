"""Reversible actions: each one can read the current state, apply a setting and revert it.

Variable data reaches PowerShell only through $env:MAPACHE_* (with splatting for parameter names).
Registry writes use reg.exe with an argument list, no shell.
"""
import json

from ...core.fs import stat_size
from ...core.paths import SD
from ...core.proc import powershell, run_cmd
from ...core.winreg_util import full_key, reg_flag, reg_value_typed, winreg
from ...i18n import t
from ...ui.console import GRY, YEL

HIVES = {}
if winreg is not None:
    HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
VIEW64 = getattr(winreg, "KEY_WOW64_64KEY", 0)


class Action:
    kind = ""

    def params(self) -> dict:
        return {}

    def read(self):
        """Current state, JSON serializable."""
        raise NotImplementedError

    def is_applied(self, state=None) -> bool:
        raise NotImplementedError

    def apply(self, log) -> bool:
        raise NotImplementedError

    def revert(self, before, log) -> bool:
        raise NotImplementedError

    def describe(self) -> str:
        return self.kind

    def to_dict(self) -> dict:
        return {"kind": self.kind, **self.params()}


# --- Registry ---

class RegValue(Action):
    kind = "reg"

    def __init__(self, hive: str, path: str, name: str, rtype: str, value, view: int = None, default=None,
                 accept=None):
        self.hive, self.path, self.name, self.rtype, self.value = hive, path, name, rtype, value
        # other values that also count as applied (e.g. a stricter one)
        self.accept = list(accept) if accept else None
        self.view = VIEW64 if view is None and hive == "HKLM" else (view or 0)
        self.default = default  # Windows behavior when the value is missing

    def params(self):
        return dict(hive=self.hive, path=self.path, name=self.name, rtype=self.rtype, value=self.value, view=self.view,
                    default=self.default, accept=self.accept)

    def describe(self):
        return f"{self.hive}\\{self.path}\\{self.name} = {self.value}"

    def read(self):
        h = HIVES.get(self.hive)
        cur = reg_value_typed(h, self.path, self.name, self.view) if h is not None else None
        if cur is None:
            return {"exists": False}
        val, typ = cur
        if isinstance(val, bytes):
            val = val.hex()
        return {"exists": True, "type": typ, "value": val}

    def is_applied(self, state=None):
        st = state if state is not None else self.read()
        if not st.get("exists"):
            return self.default is not None and str(self.default) == str(self.value)
        ok = [str(self.value)] + [str(x) for x in self.accept or ()]
        return str(st.get("value")) in ok

    def _add(self, rtype, value, log) -> bool:
        key = full_key(HIVES.get(self.hive), self.path) if self.hive in HIVES else f"{self.hive}\\{self.path}"
        return run_cmd(["reg", "add", key, "/v", self.name, "/t", rtype, "/d", str(value), "/f",
                        *reg_flag(self.view)], log) == 0

    def apply(self, log):
        return self._add(self.rtype, self.value, log)

    def revert(self, before, log):
        key = full_key(HIVES.get(self.hive), self.path) if self.hive in HIVES else f"{self.hive}\\{self.path}"
        if not before.get("exists"):
            if not self.read().get("exists") and not log.dry:
                return True
            return run_cmd(["reg", "delete", key, "/v", self.name, "/f", *reg_flag(self.view)], log) == 0
        typ = before.get("type", self.rtype)
        if typ not in ("REG_DWORD", "REG_QWORD", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY"):
            log(t("harden.cant_revert_type", what=self.describe(), type=typ), YEL)
            return False
        return self._add(typ, before.get("value"), log)


# --- Defender ---
_mp = {}


def mp_pref(refresh=False) -> dict:
    """Get-MpPreference, cached per session."""
    if refresh or not _mp:
        _mp.clear()
        try:
            out = powershell("$p = Get-MpPreference -ErrorAction Stop; [ordered]@{ PUAProtection = [int]$p.PUAProtection;"
                             " AsrIds = @($p.AttackSurfaceReductionRules_Ids); "
                             "AsrActions = @($p.AttackSurfaceReductionRules_Actions) } | ConvertTo-Json -Compress",
                             timeout=120).stdout.strip()
            _mp.update(json.loads(out) if out.startswith("{") else {"__error": out[:200]})
        except (OSError, ValueError) as e:
            _mp["__error"] = str(e)
    return _mp


def _ps_ok(script, env, log, shown) -> bool:
    if log.dry:
        log(t("proc.sim_run", cmd=shown), GRY)
        return True
    log(f"$ {shown}", GRY)
    r = powershell(script + "; if ($?) { 'MAPACHE_OK' }", env=env, timeout=600)
    if "MAPACHE_OK" not in r.stdout:
        for line in (r.stderr or r.stdout).strip().splitlines()[-3:]:
            log(f"  {line}", GRY)
        return False
    return True


class MpPref(Action):
    kind = "mp"

    def __init__(self, param: str, value):
        self.param, self.value = param, value

    def params(self):
        return dict(param=self.param, value=self.value)

    def describe(self):
        return f"Set-MpPreference -{self.param} {self.value}"

    def read(self):
        return {"value": mp_pref().get(self.param)}

    def is_applied(self, state=None):
        st = state if state is not None else self.read()
        return str(st.get("value")) == str(self.value)

    def _set(self, value, log):
        ok = _ps_ok("$p = @{}; $p[$env:MAPACHE_P] = [int]$env:MAPACHE_V; Set-MpPreference @p -ErrorAction Stop",
                    {"MAPACHE_P": self.param, "MAPACHE_V": str(value)}, log, f"Set-MpPreference -{self.param} {value}")
        mp_pref(refresh=not log.dry)
        return ok

    def apply(self, log):
        return self._set(self.value, log)

    def revert(self, before, log):
        return True if before.get("value") is None else self._set(before["value"], log)


class AsrRule(Action):
    """ASR rule: 0 off, 1 block, 2 audit, 6 warn."""
    kind = "asr"

    def __init__(self, guid: str, action: int):
        self.guid, self.action = guid.lower(), int(action)

    def params(self):
        return dict(guid=self.guid, action=self.action)

    def describe(self):
        return f"ASR {self.guid} = {self.action}"

    def read(self):
        mp = mp_pref()
        ids = [str(x).lower() for x in (mp.get("AsrIds") or []) if x]
        acts = [x for x in (mp.get("AsrActions") or []) if x is not None]
        for i, g in enumerate(ids):
            if g == self.guid and i < len(acts):
                return {"action": int(acts[i])}
        return {"action": None}

    def is_applied(self, state=None):
        st = state if state is not None else self.read()
        cur = st.get("action")
        # never downgrade block to audit
        return cur == self.action or (self.action == 2 and cur in (1, 6))

    def _set(self, action, log):
        ok = _ps_ok("Add-MpPreference -AttackSurfaceReductionRules_Ids $env:MAPACHE_G "
                    "-AttackSurfaceReductionRules_Actions ([int]$env:MAPACHE_A) -ErrorAction Stop",
                    {"MAPACHE_G": self.guid, "MAPACHE_A": str(action)}, log, f"Add-MpPreference ASR {self.guid} = {action}")
        mp_pref(refresh=not log.dry)
        return ok

    def apply(self, log):
        return self._set(self.action, log)

    def revert(self, before, log):
        if before.get("action") is None:
            ok = _ps_ok("Remove-MpPreference -AttackSurfaceReductionRules_Ids $env:MAPACHE_G -ErrorAction Stop",
                        {"MAPACHE_G": self.guid}, log, f"Remove-MpPreference ASR {self.guid}")
            mp_pref(refresh=not log.dry)
            return ok
        return self._set(before["action"], log)


# --- Optional features ---
_features = {}


def feature_states(refresh=False) -> dict:
    if refresh or not _features:
        _features.clear()
        try:
            out = powershell("@(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.FeatureName -in "
                             "@('SMB1Protocol','MicrosoftWindowsPowerShellV2Root') } | Select-Object FeatureName, "
                             "@{n='State';e={[string]$_.State}}) | ConvertTo-Json -Compress", timeout=300).stdout.strip()
            data = json.loads(out) if out else []
            for d in data if isinstance(data, list) else [data]:
                _features[d["FeatureName"]] = d["State"]
            _features["__ok"] = True
        except (OSError, ValueError, KeyError, TypeError):
            _features["__ok"] = False
    return _features


class Feature(Action):
    kind = "feature"

    def __init__(self, name: str, enabled: bool = False):
        self.name, self.enabled = name, enabled

    def params(self):
        return dict(name=self.name, enabled=self.enabled)

    def describe(self):
        return f"{'Enable' if self.enabled else 'Disable'}-WindowsOptionalFeature {self.name}"

    def read(self):
        st = feature_states()
        return {"state": st.get(self.name, "Absent" if st.get("__ok") else None)}

    def is_applied(self, state=None):
        st = (state if state is not None else self.read()).get("state")
        if st is None:
            return False
        return (st == "Enabled") == self.enabled or (not self.enabled and st in ("Absent", "DisabledWithPayloadRemoved"))

    def _set(self, enable, log):
        verb = "Enable" if enable else "Disable"
        ok = _ps_ok(f"{verb}-WindowsOptionalFeature -Online -FeatureName $env:MAPACHE_F -NoRestart -ErrorAction Stop"
                    " | Out-Null", {"MAPACHE_F": self.name}, log, f"{verb}-WindowsOptionalFeature -Online -FeatureName "
                                                                  f"{self.name} -NoRestart")
        feature_states(refresh=not log.dry)
        return ok

    def apply(self, log):
        return self._set(self.enabled, log)

    def revert(self, before, log):
        st = before.get("state")
        if st in (None, "Absent"):
            return True
        return self._set(st == "Enabled", log)


# --- Firewall ---

class FirewallOn(Action):
    """All profiles enabled and blocking inbound by default."""
    kind = "firewall"

    def describe(self):
        return "Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block"

    def read(self):
        try:
            out = powershell("@(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, "
                             "@{n='Enabled';e={[string]$_.Enabled}}, @{n='In';e={[string]$_.DefaultInboundAction}})"
                             " | ConvertTo-Json -Compress", timeout=120).stdout.strip()
            data = json.loads(out) if out else []
            return {"profiles": data if isinstance(data, list) else [data]}
        except (OSError, ValueError):
            return {"profiles": None}

    def is_applied(self, state=None):
        profs = (state if state is not None else self.read()).get("profiles")
        return bool(profs) and all(p.get("Enabled") == "True" and p.get("In") in ("Block", "NotConfigured")
                                   for p in profs)

    def apply(self, log):
        return _ps_ok("Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -ErrorAction Stop", {},
                      log, self.describe())

    def revert(self, before, log):
        profs = before.get("profiles") or []
        return _ps_ok("$ps = $env:MAPACHE_FW | ConvertFrom-Json; foreach ($p in $ps) { Set-NetFirewallProfile "
                      "-Name $p.Name -Enabled $p.Enabled -DefaultInboundAction $p.In -ErrorAction Stop }",
                      {"MAPACHE_FW": json.dumps(profs)}, log, "Set-NetFirewallProfile (valores anteriores)")


# --- Hibernation ---

class HibernateOff(Action):
    kind = "hibernate"

    def describe(self):
        return "powercfg /h off"

    def read(self):
        return {"on": bool(stat_size(SD + "\\hiberfil.sys"))}

    def is_applied(self, state=None):
        return not (state if state is not None else self.read()).get("on")

    def apply(self, log):
        return run_cmd(["powercfg", "/h", "off"], log) == 0

    def revert(self, before, log):
        return True if not before.get("on") else run_cmd(["powercfg", "/h", "on"], log) == 0


KINDS = {c.kind: c for c in (RegValue, MpPref, AsrRule, Feature, FirewallOn, HibernateOff)}


def from_dict(d: dict) -> Action:
    d = dict(d)
    cls = KINDS[d.pop("kind")]
    return cls(**d) if d else cls()
