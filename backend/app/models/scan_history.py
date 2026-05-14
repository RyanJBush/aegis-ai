from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ScanHistory(Base):
    __tablename__ = "scan_history"

    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scan_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
