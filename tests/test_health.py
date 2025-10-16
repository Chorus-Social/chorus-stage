# tests/test_health.py
from typing import Any
import pytest


@pytest.mark.asyncio
async def test_root_responds(client: Any) -> None:
    """Verify that the root endpoint responds with either 200 or 404."""
    r = await client.get("/")
    assert r.status_code in {200, 404}  # depending on your implementation