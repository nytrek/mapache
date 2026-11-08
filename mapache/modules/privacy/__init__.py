"""Privacy: telemetry, ads, activity history and browser policies, on the hardening engine."""
from ..harden import Suite, run as _run
from .rules import GUIDES, LEVELS, RULES

PRIVACY = Suite("privacy", RULES, GUIDES, LEVELS)


def run(ctx):
    _run(ctx, suite=PRIVACY)
