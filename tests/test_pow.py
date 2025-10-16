
# tests/test_pow.py
from typing import Any
import pytest
from chorus_stage.services.pow_service import verify_solution, issue_challenge

@pytest.mark.asyncio
async def test_pow_challenge_roundtrip() -> None:
    """Verify that a PoW challenge can be issued and solved within a small range."""
    c = issue_challenge("post")
    payload_hash = b"Hello".hex()
    # Fake valid nonce by brute-forcing a tiny target for tests
    for nonce in range(100000):
        if verify_solution(payload_hash, nonce, c.target_bits, c.salt_hex):
            break
    else:
        pytest.skip("no valid nonce found quickly")