"""Action log: printed and written to %APPDATA%\\Mapache\\logs."""
import time
from pathlib import Path

from ..ui.console import R
from .paths import APP_DIR


def new_log_path(prefix: str) -> Path:
    return APP_DIR / "logs" / f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}.log"


class Log:
    def __init__(self, path: Path, dry: bool):
        self.dry, self.path = dry, path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(path, "a", encoding="utf-8")
        self.f.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')}{'  (SIMULATION)' if dry else ''} =====\n")

    def __call__(self, msg: str, col: str = ""):
        print(f"      {col}{msg}{R}")
        self.f.write(f"{time.strftime('%H:%M:%S')}  {msg}\n")
        self.f.flush()

    def mark(self, title: str):
        self.f.write(f"--- {title}\n")

    def close(self):
        try:
            self.f.close()
        except OSError:
            pass
