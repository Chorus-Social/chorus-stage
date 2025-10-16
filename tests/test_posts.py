# tests/test_posts.py
from typing import Any
import pytest
from chorus_stage.schemas.post import PostCreate


@pytest.mark.asyncio
async def test_create_post_success(client: Any) -> None:
    """Ensure a post can be created successfully and returns the expected response."""
    payload = PostCreate(
        author_pubkey_hex="ab" * 32,
        body_md="Hello Chorus!",
        signature_hex="cd" * 64,
    )
    res = await client.post("/api/v1/posts", json=payload.model_dump())
    assert res.status_code == 201
    data = res.json()
    assert "id" in data
    assert data["body_md"] == "Hello Chorus!"