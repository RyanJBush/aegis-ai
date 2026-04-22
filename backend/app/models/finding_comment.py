from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class FindingComment(Base):
    __tablename__ = "finding_comments"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    author_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
