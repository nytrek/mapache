"""Shared helpers for cleaner detectors."""
from functools import partial

from ...core.fs import clear_paths, exists
from ...core.model import Item


def cache_item(ctx, group, title, paths, level, note, action=None, admin=False, order=50) -> list:
    """Item that empties the given folders (if they exist)."""
    paths = [p for p in paths if exists(p)]
    if not paths:
        return []
    return [Item(group, title, ctx.sizes(paths), level, note,
                 action or partial(clear_paths, paths), admin=admin, order=order)]
