"""Shared data types."""
from dataclasses import dataclass


@dataclass
class Item:
    """Something that can be cleaned or removed. `action(log)` performs it."""
    group: str  # group id (translated on display)
    title: str
    size: int  # bytes to free; -1 = unknown
    level: str  # "rec" recommended | "opt" optional
    note: str
    action: object
    admin: bool = False
    order: int = 50  # execution order
    selected: bool = False
    tag: str = ""  # optional label that replaces the recommended/optional column
    key: object = None  # optional source object (e.g. a Program)


@dataclass
class BigFile:
    path: str
    size: int
    mtime: float
    ctime: float
