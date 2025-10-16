"""Order index generator.

Implement a monotonic 128-bit counter backed by the database or Redis.

Functions here are deliberately narrow so you can test them in isolation.
"""
from __future__ import annotations

async def next_order_index() -> int:
    """Return the next strictly increasing 128-bit integer.

    Constraints
    ----------
    - Monotonic across the entire system.
    - Survives restarts.
    - Suitable for sorting (no timestamps required).

    Implementation notes
    --------------------
    MVP may use a Postgres sequence + padding. Later, migrate to a k-ordered ID generator.

    Returns
    -------
    int
        The next order index value.
    """
    raise NotImplementedError("Implement next_order_index()")
