# models/rate.py
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import BigInteger, Text
from chorus_stage.db.session import Base

class NonceReplay(Base):
    __tablename__ = "nonce_replay"
    # (pubkey_hex, client_nonce_hash) -> existence means used. TTL can be Redis only, but durable backup is fine too.
    pubkey_hex: Mapped[str] = mapped_column(Text, primary_key=True)
    nonce_hash_hex: Mapped[str] = mapped_column(Text, primary_key=True)
    # Optional: last seen day_seq/hour_seq if you want server-side expunges without timestamps
    day_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    hour_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)