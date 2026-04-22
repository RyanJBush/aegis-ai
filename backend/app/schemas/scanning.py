from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=255)
    payload: str = Field(min_length=1, max_length=20000)
    profile: Literal["quick", "standard", "deep"] = "standard"
    baseline_scan_id: int | None = None
    suppression_keys: list[str] = Field(default_factory=list, max_length=100)


class ScanDiffSummary(BaseModel):
    baseline_scan_id: int | None = None
    new_findings: int = 0
    repeated_findings: int = 0
    resolved_findings: int = 0


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
    diff_summary: ScanDiffSummary | None = None


class ScanStatusUpdateRequest(BaseModel):
    status: Literal["reviewed"]


class ScanJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int | None = None
    requested_by_user_id: int
    status: str
    failure_reason: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class PolicyGateRequest(BaseModel):
    max_allowed_severity: Literal["low", "medium", "high", "critical"] = "high"
    fail_on_open: bool = True


class CIGateReport(BaseModel):
    scan_id: int
    passed: bool
    blocking_findings: int
    summary: dict[str, int]


class SuppressionExport(BaseModel):
    scan_id: int
    suppression_keys: list[str]


class ScanTrendPoint(BaseModel):
    day: date
    scans: int
    findings: int
    avg_duration_ms: float


class ScanTrendResponse(BaseModel):
    points: list[ScanTrendPoint]


class ScanReportBundle(BaseModel):
    scan_id: int
    generated_at: datetime
    findings: list[dict]


class SarifReport(BaseModel):
    scan_id: int
    sarif: dict


class DevSecOpsSnippetScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=255)
    snippet: str = Field(min_length=1, max_length=50000)
    snippet_type: Literal["code", "config"] = "code"
    profile: Literal["quick", "standard", "deep"] = "deep"
    baseline_scan_id: int | None = None
    suppression_keys: list[str] = Field(default_factory=list, max_length=100)


class RemediationChecklistResponse(BaseModel):
    scan_id: int
    checklist: list[str]
