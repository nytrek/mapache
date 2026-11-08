"""Translations, loaded from locales/<lang>.json."""
import json
from pathlib import Path

LANGS = {"es": "Español", "en": "English"}
_DIR = Path(__file__).parent / "locales"
_cur = "es"
_tables = {}


def _load(lang: str) -> dict:
    if lang not in _tables:
        try:
            _tables[lang] = json.loads((_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _tables[lang] = {}
    return _tables[lang]


def set_lang(lang: str):
    global _cur
    _cur = lang if lang in LANGS else "en"


def get_lang() -> str:
    return _cur


def t(key: str, /, **kw) -> str:  # positional-only so texts can use a {key} placeholder
    s = _load(_cur).get(key) or _load("en").get(key) or key
    if kw:
        try:
            return s.format(**kw)
        except (KeyError, IndexError, ValueError):
            return s
    return s


def has(key: str) -> bool:
    return key in _load(_cur) or key in _load("en")


def detect_lang() -> str:
    """Windows UI language (or the system locale elsewhere)."""
    try:
        import ctypes
        lid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        return "es" if (lid & 0x3FF) == 0x0A else "en"
    except Exception:
        import locale
        loc = (locale.getlocale()[0] or "").lower()
        return "es" if loc.startswith(("es", "spanish")) else "en"
