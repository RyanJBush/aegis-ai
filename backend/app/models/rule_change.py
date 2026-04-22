from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class RuleChangeEvent(Base):
    __tablename__ = "rule_change_events"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    actor_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    rule_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    old_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
