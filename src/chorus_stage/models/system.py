# models/system.py
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import BigInteger
from chorus_stage.db.session import Base

class SystemClock(Base):
    __tablename__ = "system_clock"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, default=1)
    day_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    hour_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)