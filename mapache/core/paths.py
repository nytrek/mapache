"""System paths and shared constants."""
import os
from pathlib import Path

IS_WIN = os.name == "nt"
ENV = os.environ.get

SD = ENV("SystemDrive", "C:")
SYSROOT = SD + "\\"
HOME = Path(ENV("USERPROFILE", str(Path.home())))
LOCAL = Path(ENV("LOCALAPPDATA", str(HOME / "AppData" / "Local")))
ROAMING = Path(ENV("APPDATA", str(HOME / "AppData" / "Roaming")))
PD = Path(ENV("PROGRAMDATA", SD + "\\ProgramData"))
WIN = Path(ENV("WINDIR", SD + "\\Windows"))
PF = Path(ENV("ProgramFiles", SD + "\\Program Files"))
PF86 = Path(ENV("ProgramFiles(x86)", SD + "\\Program Files (x86)"))
TEMP = Path(ENV("TEMP", str(LOCAL / "Temp")))
USERS = Path(SD + "\\Users")

# app data folder (config and logs)
APP_DIR = Path(ENV("APPDATA", str(Path.home()))) / "Mapache"

KB, MB, GB = 1024, 1024 ** 2, 1024 ** 3
DAY = 86400

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
CLOUD_ATTRS = 0x1000 | 0x40000 | 0x400000
SKIP_TAGS = {0xA0000003, 0xA000000C}  # junctions and symlinks are not followed
VM_EXT = {".vdi", ".vmdk", ".vhd", ".vhdx", ".qcow2"}
