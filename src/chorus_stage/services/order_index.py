"""Monotonic order index generator helpers."""

async def next_order_index() -> int:
    """Return the next strictly increasing 128-bit integer.

    Returns:
        The next globally unique order index.

    Raises:
        NotImplementedError: Always, until persistence is wired up.

    Notes:
        The eventual implementation should be monotonic across the entire system,
        survive restarts, and provide a sortable identifier without timestamps.
    """
    raise NotImplementedError("Implement next_order_index()")
