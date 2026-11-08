"""Optimization: startup programs, third-party tasks and power plan, on the hardening engine."""
from ..harden import Suite, run as _run
from .rules import GUIDES, LEVELS, RULES, dynamic

OPTIMIZE = Suite("optimize", RULES, GUIDES, LEVELS, dynamic=dynamic)


def run(ctx):
    _run(ctx, suite=OPTIMIZE)
