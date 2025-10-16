from typing import Any
import pytest


@pytest.mark.asyncio
async def test_create_post(client: Any) -> None:
    """Smoke test to ensure a post can be created successfully."""
    payload = {
        "author_pubkey_hex": "ab" * 32,
        "body_md": "hello chorus",
        "signature_hex": "cd" * 64,
    }
    r = await client.post("/api/v1/posts", json=payload)
    assert r.status_code == 201
    body = r.json()
    assert body["body_md"] == "hello chorus"
    assert "order_index" in body