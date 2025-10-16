# models/message.py
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import BigInteger, LargeBinary, Text, ForeignKey, Numeric, Boolean
from chorus_stage.db.session import Base

class DirectMessage(Base):
    __tablename__ = "direct_message"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    order_index: Mapped[int] = mapped_column(Numeric(38,0), nullable=False, unique=True)

    sender_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), nullable=False)
    recipient_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("user_account.id"), nullable=False)

    # Minimal routing metadata; all content is E2E payload
    # clients encrypt with recipient PGP, optionally sign with sender Ed25519
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Optional associated nonce or header blob if you use libsodium box or hybrid PGP schemes
    header_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    delivered: Mapped[bool] = mapped_column(default=False, nullable=False)