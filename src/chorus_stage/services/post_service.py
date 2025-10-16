"""Service-level helpers for creating posts."""
from __future__ import annotations

import binascii
import hashlib
from dataclasses import dataclass

from chorus_stage.repositories.post_repo import PostRepository
from chorus_stage.services.order_index import next_order_index
from chorus_stage.services.signing import verify_request_signature


@dataclass(frozen=True)
class CreatePostResult:
    """Lightweight container for the identifier returned from the repository."""

    id: int
    order_index: int


async def create_post(
    *,
    repo: PostRepository,
    author_pubkey_hex: str,
    body_md: str,
    signature_hex: str,
    payload_for_sig: bytes,
) -> CreatePostResult:
    """Create a post after validating the caller's signature.

    Args:
        repo: Repository used to persist the post.
        author_pubkey_hex: Hex-encoded public key of the author.
        body_md: Markdown body submitted by the client.
        signature_hex: Hex-encoded signature covering the payload.
        payload_for_sig: Canonical payload bytes used for signature verification.

    Returns:
        Identifiers required by the API layer.

    Raises:
        ValueError: If the signature fails verification.

    Notes:
        Proof-of-work and replay prevention occur upstream; this function assumes they
        have already been enforced.
    """
    if not verify_request_signature(author_pubkey_hex, payload_for_sig, signature_hex):
        raise ValueError("Invalid signature")

    # Hash the content to provide an immutable fingerprint for deduplication checks.
    content_hash = hashlib.sha256(body_md.encode("utf-8")).digest()
    order_index = await next_order_index()
    author_pubkey = binascii.unhexlify(author_pubkey_hex)
    post = await repo.create(
        author_pubkey=author_pubkey,
        body_md=body_md,
        content_hash=content_hash,
        order_index=order_index,
    )
    return CreatePostResult(id=post.id, order_index=int(post.order_index))
