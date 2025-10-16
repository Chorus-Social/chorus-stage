# tests/test_feed_rising.py
from typing import Any
import pytest


@pytest.mark.asyncio
async def test_rising_feed(client: Any, db: Any) -> None:
    """Ensure rising feed returns a list of posts with expected limit."""
    for i in range(5):
        await client.post(
            "/api/v1/posts",
            json={
                "author_pubkey_hex": "ab" * 32,
                "body_md": f"Post {i}",
                "signature_hex": "cd" * 64,
            },
        )
    res = await client.get("/api/v1/feed/rising?limit=3")
    assert res.status_code == 200
    posts = res.json()
    assert isinstance(posts, list)
    assert len(posts) <= 3