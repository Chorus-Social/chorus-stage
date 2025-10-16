"""Models describing direct messages between users."""
from sqlalchemy import BigInteger, ForeignKey, LargeBinary, Numeric
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base


class DirectMessage(Base):
    """Encrypted message exchanged between two users."""

    __tablename__ = "direct_message"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_index: Mapped[int] = mapped_column(Numeric(38, 0), nullable=False, unique=True)

    sender_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), nullable=False)
    recipient_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), nullable=False)

    # Minimal routing metadata; all content is end-to-end encrypted payload.
    # Clients encrypt with the recipient's PGP key and optionally sign with the sender's Ed25519 key.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Optional associated nonce or header blob for hybrid encryption schemes.
    header_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    delivered: Mapped[bool] = mapped_column(default=False, nullable=False)
