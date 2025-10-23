# src/chorus_stage/models/replay_protection.py
"""Models supporting replay protection and rate limiting."""


from sqlalchemy import BigInteger, Text
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base


class NonceReplay(Base):
    """Record indicating that a client nonce has already been used."""

    __tablename__ = "nonce_replay"

    # (pubkey_hex, client_nonce_hash) -> existence means "already seen".
    pubkey_hex: Mapped[str] = mapped_column(Text, primary_key=True)
    nonce_hash_hex: Mapped[str] = mapped_column(Text, primary_key=True)
    # Optional time-bucket fields that enable server-side expiry policies without timestamps.
    day_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    hour_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
