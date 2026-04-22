from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_workspace_id, require_roles
from app.db.session import get_db
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.models.user import Role, User
from app.models.vulnerability import Vulnerability
from app.schemas.scanning import (
    CIGateReport,
    PolicyGateRequest,
    SarifReport,
    DevSecOpsSnippetScanRequest,
    ScanDiffSummary,
    ScanJobRead,
    ScanReportBundle,
    ScanRequest,
    ScanResponse,
    ScanStatusUpdateRequest,
    ScanTrendResponse,
    SuppressionExport,
    RemediationChecklistResponse,
)
from app.schemas.vulnerability import KpiSummary
from app.services.scanning_service import ScanningService
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter()


def _run(payload: ScanRequest, user: User, workspace_id: int, db: Session) -> ScanResponse:
    return ScanningService.run_scan(db=db, user_id=user.id, workspace_id=workspace_id, payload=payload)


@router.post("/run", response_model=ScanResponse)
def run_scan(
    payload: ScanRequest,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst})),
    db: Session = Depends(get_db),
) -> ScanResponse:
    return _run(payload=payload, user=user, workspace_id=workspace_id, db=db)


@router.post("/queue", response_model=ScanJobRead)
def queue_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst})),
    db: Session = Depends(get_db),
) -> ScanJobRead:
    job = ScanningService.enqueue_scan(db=db, user_id=user.id, workspace_id=workspace_id, payload=payload)
    background_tasks.add_task(ScanningService.process_queued_job, job.id, user.id, workspace_id, payload)
    return job


@router.post("/devsecops/snippet", response_model=ScanResponse)
def run_devsecops_snippet_scan(
    payload: DevSecOpsSnippetScanRequest,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer})),
    db: Session = Depends(get_db),
) -> ScanResponse:
    return ScanningService.run_snippet_scan(
        db=db,
        user_id=user.id,
        workspace_id=workspace_id,
        payload=payload,
    )


@router.post("/devsecops/upload", response_model=ScanResponse)
async def run_devsecops_upload_scan(
    target: str = Form(...),
    snippet_type: str = Form(default="code"),
    profile: str = Form(default="deep"),
    file: UploadFile = File(...),
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer})),
    db: Session = Depends(get_db),
) -> ScanResponse:
    content = (await file.read()).decode("utf-8", errors="ignore")
    payload = DevSecOpsSnippetScanRequest(
        target=target,
        snippet=content,
        snippet_type="config" if snippet_type == "config" else "code",
        profile=profile if profile in {"quick", "standard", "deep"} else "deep",
    )
    return ScanningService.run_snippet_scan(
        db=db,
        user_id=user.id,
        workspace_id=workspace_id,
        payload=payload,
    )


@router.get("", response_model=list[ScanResponse])
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> list[ScanResponse]:
    order = Scan.created_at.asc() if sort_dir == "asc" else Scan.created_at.desc()
    scans = (
        db.query(Scan)
        .filter(Scan.workspace_id == workspace_id)
        .order_by(order)
        .offset(offset)
        .limit(limit)
        .all()
    )
    result: list[ScanResponse] = []
    for scan in scans:
        findings_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.scan_id == scan.id).scalar() or 0
        result.append(
            ScanResponse(
                id=scan.id,
                target=scan.target,
                profile=scan.profile,
                status=scan.status,
                created_at=scan.created_at,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                duration_ms=scan.duration_ms,
                failure_reason=scan.failure_reason,
                vulnerabilities_found=int(findings_count),
            )
        )
    return result


@router.get("/jobs/{job_id}", response_model=ScanJobRead)
def get_scan_job(
    job_id: int,
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> ScanJobRead:
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    return ScanJobRead.model_validate(job)


@router.post("/start", response_model=ScanResponse)
def start_scan(
    payload: ScanRequest,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst})),
    db: Session = Depends(get_db),
) -> ScanResponse:
    return _run(payload=payload, user=user, workspace_id=workspace_id, db=db)


@router.patch("/{scan_id}/status", response_model=ScanResponse)
def update_scan_status(
    scan_id: int,
    payload: ScanStatusUpdateRequest,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst})),
    db: Session = Depends(get_db),
) -> ScanResponse:
    if payload.status != "reviewed":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported status transition")
    scan = ScanningService.mark_reviewed(db=db, user_id=user.id, workspace_id=workspace_id, scan_id=scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    findings_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.scan_id == scan.id).scalar() or 0
    return ScanResponse(
        id=scan.id,
        target=scan.target,
        profile=scan.profile,
        status=scan.status,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_ms=scan.duration_ms,
        failure_reason=scan.failure_reason,
        vulnerabilities_found=int(findings_count),
    )


@router.get("/{scan_id}/diff", response_model=ScanDiffSummary)
def get_scan_diff(
    scan_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> ScanDiffSummary:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.workspace_id == workspace_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    current_rows = db.query(Vulnerability.dedupe_key).filter(Vulnerability.scan_id == scan.id).all()
    current_keys = {row[0] for row in current_rows}
    return ScanningService.build_diff_summary(db=db, baseline_scan_id=scan.baseline_scan_id, current_dedupe_keys=current_keys)


@router.post("/{scan_id}/policy-gate", response_model=CIGateReport)
def evaluate_policy_gate(
    scan_id: int,
    payload: PolicyGateRequest,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer})),
    db: Session = Depends(get_db),
) -> CIGateReport:
    report = ScanningService.build_policy_gate_report(db=db, workspace_id=workspace_id, scan_id=scan_id, payload=payload)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return report


@router.get("/{scan_id}/reports/json", response_model=ScanReportBundle)
def export_json_report(
    scan_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> ScanReportBundle:
    report = ScanningService.build_report_bundle(db=db, workspace_id=workspace_id, scan_id=scan_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return report


@router.get("/{scan_id}/reports/sarif", response_model=SarifReport)
def export_sarif_report(
    scan_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> SarifReport:
    report = ScanningService.build_sarif_report(db=db, workspace_id=workspace_id, scan_id=scan_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return report


@router.get("/{scan_id}/remediation-checklist", response_model=RemediationChecklistResponse)
def get_remediation_checklist(
    scan_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> RemediationChecklistResponse:
    checklist = ScanningService.build_remediation_checklist(db=db, workspace_id=workspace_id, scan_id=scan_id)
    if not checklist:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return checklist


@router.get("/{scan_id}/suppressions", response_model=SuppressionExport)
def export_suppressions(
    scan_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer})),
    db: Session = Depends(get_db),
) -> SuppressionExport:
    exported = ScanningService.export_suppressions(db=db, workspace_id=workspace_id, scan_id=scan_id)
    if not exported:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return exported


@router.get("/history/trends", response_model=ScanTrendResponse)
def get_scan_trends(
    days: int = Query(default=14, ge=1, le=90),
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> ScanTrendResponse:
    return ScanningService.build_scan_trends(db=db, workspace_id=workspace_id, days=days)


@router.get("/kpi/summary", response_model=KpiSummary)
def get_kpi_summary(
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> KpiSummary:
    return VulnerabilityService.build_kpi_summary(db=db, workspace_id=workspace_id)
