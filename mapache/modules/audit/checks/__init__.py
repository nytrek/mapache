"""Check registry. Each check is `fn(facts) -> R`, registered with @check.

Statuses: pass, warn (half credit), fail, info and unknown (not scored).
"""
from dataclasses import dataclass, field

CATEGORIES = ["crypto", "isolation", "defender", "network", "system", "memory", "persistence"]
REGISTRY = []


@dataclass
class R:
    status: str
    detail: str = ""
    items: list = field(default_factory=list)
    weight: int = None  # weight override for context (e.g. no BitLocker)
    admin: bool = False  # True = needs admin (when status is unknown)


@dataclass
class Result:
    id: str
    cat: str
    weight: int
    status: str
    detail: str = ""
    items: list = field(default_factory=list)
    admin: bool = False
    refs: tuple = ()
    harden: str = ""


def check(cid: str, cat: str, weight: int, refs=(), harden: str = ""):
    def deco(fn):
        REGISTRY.append((cid, cat, weight, tuple(refs), harden, fn))
        return fn
    return deco


def run_all(facts, only=None) -> list:
    from ....i18n import t
    from . import crypto, defender, isolation, memory, network, persistence, system  # noqa: F401
    out = []
    for cid, cat, weight, refs, harden, fn in REGISTRY:
        if only and cid not in only:
            continue
        try:
            r = fn(facts)
        except Exception as e:  # a broken check must not stop the audit
            r = R("unknown", t("audit.rule_error", err=f"{type(e).__name__}: {e}"))
        out.append(Result(cid, cat, r.weight if r.weight is not None else weight, r.status, r.detail,
                          list(r.items), r.admin, refs, harden))
    return out


def score(results) -> tuple:
    """(overall score 0-100 or None, {category: score or None})."""
    credit = {"pass": 1.0, "warn": 0.5, "fail": 0.0}

    def calc(rs):
        rs = [r for r in rs if r.status in credit and r.weight > 0]
        tot = sum(r.weight for r in rs)
        return round(100 * sum(r.weight * credit[r.status] for r in rs) / tot) if tot else None
    return calc(results), {c: calc([r for r in results if r.cat == c]) for c in CATEGORIES}
