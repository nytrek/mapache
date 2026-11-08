"""Persistent settings in %APPDATA%\\Mapache\\config.json."""
import json

from .core.paths import APP_DIR

CFG = APP_DIR / "config.json"


def load() -> dict:
    try:
        return json.loads(CFG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(**changes):
    data = load()
    data.update(changes)
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        CFG.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass
