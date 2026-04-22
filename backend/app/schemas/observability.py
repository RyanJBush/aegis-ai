from datetime import datetime

from pydantic import BaseModel, Field


class AuditLogRead(BaseModel):
    id: int
    actor_user_id: int | None = None
    action: str
    entity_type: str
    entity_id: int | None = None
    details: dict | None = None
    created_at: datetime


class ScanMetricsSummary(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    success_rate_percent: float
    average_duration_ms: float
    average_findings_per_scan: float


class RuleChangeCreate(BaseModel):
    rule_key: str = Field(min_length=2, max_length=64)
    change_type: str = Field(min_length=2, max_length=32)
    old_config: dict | None = None
    new_config: dict | None = None
    reason: str | None = Field(default=None, max_length=2000)


class RuleChangeRead(BaseModel):
    id: int
    workspace_id: int
    actor_user_id: int
    rule_key: str
    change_type: str
    old_config: dict | None = None
    new_config: dict | None = None
    reason: str | None = None
    created_at: datetime
