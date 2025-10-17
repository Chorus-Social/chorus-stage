# src/chorus_stage/models/direct_message.py
"""Models describing direct messages between users."""

from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Integer, LargeBinary, Numeric
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base
from chorus_stage.db.time import utcnow


class DirectMessage(Base):
    """Encrypted message exchanged between two users.

    Messages are stored on the server but are never decrypted, providing
    end-to-end encryption between users.
    """

    __tablename__ = "direct_message"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    order_index: Mapped[int] = mapped_column(Numeric(38, 0), nullable=False, unique=True)

    sender_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), nullable=False)
    recipient_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), nullable=False)

    # Minimal routing metadata; all content is end-to-end encrypted payload.
    # Clients encrypt with the recipient's PGP key and optionally sign with the sender's Ed25519 key.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Optional associated nonce or header blob for hybrid encryption schemes.
    header_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    delivered: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
