"""VirtualBox: repeated VMs and orphaned disks."""
import datetime as dt
import os
import re
import shutil
import subprocess
import time
from functools import partial
from pathlib import Path

from ...core.fs import PROTECTED_NAMES, del_paths, disp, exists, ikey, lp, mtime, rm
from ...core.model import Item
from ...core.paths import DAY, ENV, PF, USERS, VM_EXT
from ...i18n import t
from ...ui.console import GRN, GRY, YEL, ago

FAMILIES = ("kali", "parrot", "ubuntu", "debian", "metasploitable", "windows", "win10", "win11",
            "fedora", "blackarch", "arch", "mint", "remnux", "flare", "tails", "whonix", "centos",
            "rocky", "alma", "pfsense", "opnsense", "security onion")


def family(name: str) -> str:
    n = name.lower()
    for f in FAMILIES:
        if f in n:
            return "windows" if f.startswith("win") else f
    return n


class VBox:
    def __init__(self):
        self.exe = None
        cands = [shutil.which("VBoxManage")]
        if ENV("VBOX_MSI_INSTALL_PATH"):
            cands.append(os.path.join(ENV("VBOX_MSI_INSTALL_PATH"), "VBoxManage.exe"))
        cands.append(str(PF / "Oracle" / "VirtualBox" / "VBoxManage.exe"))
        self.exe = next((c for c in cands if c and os.path.isfile(c)), None)
        self.vms, self.disks = [], {}
        if self.exe:
            self.load()

    def call(self, *args, timeout=120):
        return subprocess.run([self.exe, *args], capture_output=True, text=True,
                              errors="replace", timeout=timeout)

    def load(self):
        self.disks = self.parse_hdds(self.call("list", "hdds").stdout)
        for name, uuid in self.parse_vms(self.call("list", "vms").stdout):
            info = self.parse_machinereadable(self.call("showvminfo", uuid, "--machinereadable").stdout)
            self.vms.append(self.make_vm(name, uuid, info))

    @staticmethod
    def parse_hdds(text: str) -> dict:
        disks = {}
        for block in re.split(r"\r?\n\s*\r?\n", text):
            kv = {}
            for line in block.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    kv[k.strip()] = v.strip()
            if "Location" in kv:
                disks[ikey(kv["Location"])] = {"uuid": kv.get("UUID", ""), "inuse": kv.get("In use by VMs", "")}
        return disks

    @staticmethod
    def parse_vms(text: str) -> list:
        out = []
        for line in text.splitlines():
            m = re.match(r'^"(.*)" \{([0-9a-fA-F-]+)\}\s*$', line.strip())
            if m:
                out.append(m.groups())
        return out

    @staticmethod
    def parse_machinereadable(text: str) -> dict:
        info = {}
        for line in text.splitlines():
            m = re.match(r'^"?([^"=]+)"?="?(.*?)"?$', line.strip())
            if m:
                # --machinereadable escapes backslashes and quotes
                info[m.group(1)] = re.sub(r'\\([\\"])', r"\1", m.group(2))
        return info

    @staticmethod
    def make_vm(name, uuid, info) -> dict:
        cfg = info.get("CfgFile", "")
        disks = [v for v in info.values() if os.path.splitext(v)[1].lower() in VM_EXT]
        last = 0.0
        try:
            last = dt.datetime.strptime(info.get("VMStateChangeTime", "")[:19], "%Y-%m-%dT%H:%M:%S") \
                .replace(tzinfo=dt.timezone.utc).timestamp()
        except ValueError:
            pass
        if not last:
            last = max([mtime(p) for p in disks + [cfg] if p] or [0.0])
        return dict(name=name, uuid=uuid, cfg=cfg, disks=disks, last=last,
                    folder=os.path.dirname(cfg) if cfg else "", state=info.get("VMState", ""))

    def is_running(self, uuid: str) -> bool:
        try:
            return uuid.lower() in self.call("list", "runningvms").stdout.lower()
        except Exception:
            return False


def is_vm_only_folder(folder: Path) -> bool:
    """True if the folder only contains files of one VM."""
    if folder.name.lower() in PROTECTED_NAMES or folder.parent == USERS or folder == USERS:
        return False
    ok_ext = {".vbox", ".vbox-prev", ".vdi", ".vmdk", ".nvram", ".sav", ".log", ".ova", ".ovf", ".mf"}
    try:
        for e in os.scandir(lp(folder)):
            if e.is_dir(follow_symlinks=False):
                if e.name.lower() not in ("logs", "snapshots"):
                    return False
            elif os.path.splitext(e.name)[1].lower() not in ok_ext and not re.search(r"\.log\.\d+$", e.name):
                return False
    except OSError:
        return False
    return True


def del_vm(vb: VBox, vm: dict, log):
    if vb.is_running(vm["uuid"]):
        log(t("vm.running_skip", name=vm["name"]), YEL)
        return
    if log.dry:
        log(t("vm.sim_unregister", name=vm["name"]), GRY)
        return
    log(f"$ VBoxManage unregistervm {vm['uuid']} --delete", GRY)
    r = vb.call("unregistervm", vm["uuid"], "--delete", timeout=1800)
    if r.returncode != 0:
        for line in (r.stderr or r.stdout).strip().splitlines()[-3:]:
            log(f"  {line}", GRY)
        log(t("vm.unregister_failed"), YEL)
        return
    log(t("vm.deleted", name=vm["name"]), GRN)
    folder = vm["folder"]
    if folder and exists(folder):
        leftovers = [f for f in os.listdir(lp(folder)) if os.path.splitext(f)[1].lower() in VM_EXT]
        if leftovers:
            log(t("vm.kept_shared", files=", ".join(leftovers)), YEL)
        elif is_vm_only_folder(Path(folder)):  # VM leftovers only (logs)
            rm(folder, log)


def detect(ctx) -> list:
    vb = ctx.vbox = VBox()
    items = []
    registered = set(vb.disks)
    for vm in vb.vms:
        registered |= {ikey(d) for d in vm["disks"]}
        if vm["cfg"]:
            registered.add(ikey(vm["cfg"]))

    fams = {}
    for vm in vb.vms:
        # A .vbox inside a shared folder (e.g. Downloads) only claims the VM files,
        # never the whole folder.
        vm["own_folder"] = bool(vm["folder"]) and is_vm_only_folder(Path(vm["folder"]))
        if vm["own_folder"]:
            fk = ikey(vm["folder"]) + os.sep
            size = ctx.size(vm["folder"]) + sum(ctx.size(d) for d in vm["disks"] if not ikey(d).startswith(fk))
        else:
            size = sum(ctx.size(p) for p in vm["disks"] + [vm["cfg"]] if p)
        vm["size"] = size
        fams.setdefault(family(vm["name"]), []).append(vm)

    for fam, vms in fams.items():
        vms.sort(key=lambda v: v["last"], reverse=True)
        newest = vms[0]
        for i, vm in enumerate(vms):
            if len(vms) > 1 and i > 0:
                level = "rec"
                note = t("vm.note_dup", n=len(vms), fam=fam, keep=newest["name"],
                         keep_ago=ago(newest["last"]), ago=ago(vm["last"]))
            else:
                level = "opt"
                note = t("vm.note_last", ago=ago(vm["last"]))
                if len(vms) > 1:
                    note += " · " + t("vm.note_newest", n=len(vms), fam=fam)
            if vm["state"] in ("running", "paused"):
                note += " · " + t("vm.note_running")
            note += f" · {disp(vm['folder'])}"
            items.append(Item("vm", t("vm.title", name=vm["name"]), vm["size"], level, note,
                              partial(del_vm, vb, vm), order=20))
            ctx.claim(vm["folder"] if vm["own_folder"] else vm["cfg"])
            for d in vm["disks"]:
                ctx.claim(d)

    for bf in ctx.scan.big if ctx.scan else []:
        p = disp(bf.path)
        if os.path.splitext(p)[1].lower() != ".vdi" or ikey(p) in registered or ctx.claimed_by(p):
            continue
        folder = Path(p).parent
        whole = is_vm_only_folder(folder)
        target = folder if whole else Path(p)
        if not vb.exe:
            level, why = "opt", t("vm.orphan_novbox")
        elif time.time() - bf.mtime < 7 * DAY:
            level, why = "opt", t("vm.orphan_recent")
        else:
            level, why = "rec", t("vm.orphan_unused", ago=ago(bf.mtime))
        title = t("vm.orphan_folder", name=folder.name) if whole else t("vm.orphan_disk", name=Path(p).name)
        items.append(Item("vm", title, ctx.size(target), level, f"{why} · {target}",
                          partial(del_paths, [target]), order=20))
        ctx.claim(target)
    return items
