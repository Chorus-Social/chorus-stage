"""Posting logic with clean contracts and clear preconditions."""
from __future__ import annotations
import hashlib, binascii
from dataclasses import dataclass

from chorus_stage.repositories.post_repo import PostRepository
from chorus_stage.services.order_index import next_order_index
from chorus_stage.services.signing import verify_request_signature

@dataclass(frozen=True)
class CreatePostResult:
    id: int
    order_index: int


async def create_post(*, repo: PostRepository, author_pubkey_hex: str, body_md: str,
                      signature_hex: str, payload_for_sig: bytes) -> CreatePostResult:
    """Create a post after verifying signature.

    Preconditions
    -------------
    - `verify_request_signature(author_pubkey_hex, payload_for_sig, signature_hex)` is True
    - `body_md` is text-only and within length limits
    - The caller has already validated PoW and replay-protection

    Returns
    -------
    CreatePostResult

    Steps
    -----
    1. Hash content to get `content_hash`.
    2. Allocate next `order_index`.
    3. Insert row via repository.

    Errors
    ------
    - Raise ValueError on signature failure or invalid inputs.
    """
    if not verify_request_signature(author_pubkey_hex, payload_for_sig, signature_hex):
        raise ValueError("Invalid signature")

    content_hash = hashlib.sha256(body_md.encode("utf-8")).digest()
    oi = await next_order_index()
    author_pubkey = binascii.unhexlify(author_pubkey_hex)
    p = await repo.create(author_pubkey=author_pubkey, body_md=body_md, content_hash=content_hash, order_index=oi)
    return CreatePostResult(id=p.id, order_index=int(p.order_index))
