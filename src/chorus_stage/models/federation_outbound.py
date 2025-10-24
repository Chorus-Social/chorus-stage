"""SQLAlchemy model for tracking outbound federation events."""

from sqlalchemy import CHAR, VARCHAR, BigInteger, LargeBinary, SmallInteger, Text
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base


class FederationOutbound(Base):
    """Record of an event sent to the Chorus Bridge for federation."""

    __tablename__ = "federation_outbound"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)  # e.g., 'PostAnnouncement'
    event_hash: Mapped[str] = mapped_column(
        CHAR(64), unique=True, nullable=False
    )  # BLAKE3 hash of the payload
    payload: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )  # Serialized FederationEnvelope
    status: Mapped[str] = mapped_column(
        VARCHAR(20), nullable=False, default="pending"
    )  # 'pending', 'accepted', 'failed'
    retry_count: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    # Note: 'submitted_at' is intentionally omitted from the model to adhere to the
    # "no real-world timestamps" principle for exposed data.
    # It can be managed internally by the database if needed for internal auditing,
    # but not part of the ORM model for privacy.
