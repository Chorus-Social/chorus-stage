"""Service-level helpers for creating posts."""
from __future__ import annotations

import binascii
import hashlib

from chorus_stage.repositories.post_repo import PostRepository
from chorus_stage.services.order_index import next_order_index
from chorus_stage.services.signing import verify_request_signature
from chorus_stage.models.post import Post
from chorus_stage.schemas.post import PostOut


async def create_post(
    *,
    repo: PostRepository,
    author_pubkey_hex: str,
    body_md: str,
    signature_hex: str,
    payload_for_sig: bytes,
) -> Post:
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
    return post


def to_post_out(post: Post) -> PostOut:
    """Convert a Post ORM instance to an API schema."""
    return PostOut.model_construct(
        id=post.id,
        order_index=int(post.order_index),
        body_md=post.body_md,
        author_pubkey_hex=post.author_pubkey.hex(),
    )
