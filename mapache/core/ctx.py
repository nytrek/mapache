"""Session context: privileges, dry-run mode and the shared scan."""
import os

from .fs import ikey, path_size
from .paths import SYSROOT
from .scan import DriveScan


class Ctx:
    def __init__(self, admin: bool, dry: bool = False):
        self.admin = admin
        self.dry = dry
        self.scan = None
        self.claimed = []  # paths already offered by a detector
        self.vbox = None

    def ensure_scan(self, root: str = SYSROOT) -> DriveScan:
        if self.scan is None:
            self.scan = DriveScan(root).run()
        return self.scan

    def invalidate(self):
        """Drop the scan after files were deleted."""
        self.scan = None

    def size(self, p) -> int:
        if self.scan is not None:
            s = self.scan.size(p)
            if s is not None:
                return s
        return path_size(p)

    def sizes(self, paths) -> int:
        return sum(self.size(p) for p in paths)

    # --- Claimed paths ---
    def claim(self, p):
        if p:
            self.claimed.append(ikey(p))

    def claimed_by(self, p) -> bool:
        n = ikey(p)
        return any(n == c or n.startswith(c + os.sep) for c in self.claimed)

    def contains_claimed(self, p) -> bool:
        n = ikey(p) + os.sep
        return any(c.startswith(n) for c in self.claimed)
