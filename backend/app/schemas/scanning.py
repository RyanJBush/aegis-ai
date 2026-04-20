from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=255)
    payload: str = Field(min_length=1, max_length=20000)
    profile: Literal["quick", "standard", "deep"] = "standard"
    baseline_scan_id: int | None = None
    suppression_keys: list[str] = Field(default_factory=list, max_length=100)


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    profile: str
    status: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    failure_reason: str | None = None
    vulnerabilities_found: int


class ScanStatusUpdateRequest(BaseModel):
    status: Literal["reviewed"]
