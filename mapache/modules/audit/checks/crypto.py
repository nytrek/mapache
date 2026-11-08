"""Encryption and boot: BitLocker, Secure Boot, TPM and kernel DMA protection."""
from ....i18n import t
from ..facts import as_list
from . import R, check

# System.Volume.BitLockerProtection: 1/6 on, 2 off, 3 encrypting, 4 decrypting, 5 suspended
BL_SHELL = {1: "on", 6: "on", 2: "off", 3: "encrypting", 4: "decrypting", 5: "suspended"}


def bitlocker_state(f):
    """'on' | 'off' | 'encrypting' | 'decrypting' | 'suspended' | None."""
    bl = f.psv("bl")
    if isinstance(bl, dict) and bl.get("ProtectionStatus"):
        vs = str(bl.get("VolumeStatus", ""))
        if "EncryptionInProgress" in vs:
            return "encrypting"
        if "DecryptionInProgress" in vs:
            return "decrypting"
        if bl["ProtectionStatus"] == "On":
            return "on"
        return "suspended" if "FullyEncrypted" in vs else "off"
    v = f.psv("blshell")
    try:
        return BL_SHELL.get(int(v))
    except (TypeError, ValueError):
        return None


@check("bitlocker", "crypto", 5, refs=("MS: BitLocker countermeasures", "ATT&CK T1005"), harden="crypto.bitlocker_pin")
def bitlocker(f):
    st = bitlocker_state(f)
    if st is None:
        return R("unknown", t("audit.need_admin"), admin=True)
    if st in ("off", "decrypting"):
        return R("fail", t("audit.bitlocker.off"))
    if st == "suspended":
        return R("fail", t("audit.bitlocker.suspended"))
    if st == "encrypting":
        return R("warn", t("audit.bitlocker.encrypting"))
    bl = f.psv("bl")
    if not isinstance(bl, dict):
        return R("pass", t("audit.bitlocker.on_unknown_pin"))
    prot = [str(p) for p in as_list(bl.get("Protectors"))]
    if any("Pin" in p or "StartupKey" in p for p in prot):
        return R("pass", t("audit.bitlocker.pin"))
    return R("warn", t("audit.bitlocker.tpm_only"), items=prot)


@check("secureboot", "crypto", 3, refs=("MS: Secure Boot",))
def secureboot(f):
    v = f.val(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    if v == 1:
        return R("pass", t("audit.on"))
    if v == 0:
        return R("fail", t("audit.off"))
    return R("fail", t("audit.secureboot.legacy"))


@check("tpm", "crypto", 2, refs=("MS: TPM",))
def tpm(f):
    devs = f.psv("tpm")
    if devs is None:
        return R("unknown", t("audit.cant_read"))
    for d in as_list(devs):
        name = str(d.get("FriendlyName", ""))
        if "trusted platform module" in name.lower():
            return R("pass" if d.get("Status") == "OK" else "warn", name)
    return R("fail", t("audit.tpm.none"))


@check("dma", "crypto", 1, refs=("MS: Kernel DMA Protection",))
def dma(f):
    v = f.dma_protection()
    if v is None:
        return R("unknown", t("audit.cant_read"))
    return R("pass", t("audit.on")) if v else R("warn", t("audit.off"))
