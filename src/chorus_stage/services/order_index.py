"""Monotonic order index generator helpers."""

from __future__ import annotations

import asyncio
import itertools

_ORDER_INDEX_COUNTER = itertools.count(start=1)
_ORDER_INDEX_LOCK = asyncio.Lock()


async def next_order_index() -> int:
    """Return the next strictly increasing 128-bit integer.

    Returns:
        The next globally unique order index.

    Notes:
        The eventual implementation should be monotonic across the entire system,
        survive restarts, and provide a sortable identifier without timestamps.
    """
    async with _ORDER_INDEX_LOCK:
        return next(_ORDER_INDEX_COUNTER)
