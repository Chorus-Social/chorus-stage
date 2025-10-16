"""System-level bookkeeping models."""
from sqlalchemy import BigInteger
from sqlalchemy.orm import Mapped, mapped_column

from chorus_stage.db.session import Base


class SystemClock(Base):
    """Monotonic counters used for coarse-grained ordering."""

    __tablename__ = "system_clock"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, default=1)
    day_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    hour_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
