# tests/test_moderation.py
from typing import Any
import pytest
from chorus_stage.core import settings


@pytest.mark.asyncio
async def test_post_hidden_when_threshold_reached(client: Any) -> None:
    """Verify that a post is hidden when harmful votes exceed the threshold."""
    # Create post
    res = await client.post(
        "/api/v1/posts",
        json={
            "author_pubkey_hex": "aa" * 32,
            "body_md": "Bad content",
            "signature_hex": "bb" * 64,
        },
    )
    pid = res.json()["id"]

    # Simulate harmful votes until hide threshold
    for _ in range(int(settings.HARMFUL_HIDE_THRESHOLD * 100) + 1):
        await client.post(f"/api/v1/moderation/{pid}/vote", json={"choice": 1})

    hidden = await client.get("/api/v1/feed/home")
    assert pid not in [p["id"] for p in hidden.json()]