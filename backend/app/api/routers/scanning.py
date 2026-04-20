from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.session import get_db
from app.models.vulnerability import Vulnerability
from app.models.user import Role, User
from app.schemas.scanning import ScanRequest, ScanResponse, ScanStatusUpdateRequest
from app.schemas.vulnerability import KpiSummary
from app.services.scanning_service import ScanningService
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter()


def _run(payload: ScanRequest, user: User, db: Session) -> ScanResponse:
    return ScanningService.run_scan(db=db, user_id=user.id, payload=payload)


@router.post("/run", response_model=ScanResponse)
def run_scan(
    payload: ScanRequest,
    user: User = Depends(require_roles({Role.admin, Role.analyst})),
    db: Session = Depends(get_db),
) -> ScanResponse:
    return _run(payload=payload, user=user, db=db)


@router.post("/start", response_model=ScanResponse)
def start_scan(
    payload: ScanRequest,
    user: User = Depends(require_roles({Role.admin, Role.analyst})),
    db: Session = Depends(get_db),
) -> ScanResponse:
    return _run(payload=payload, user=user, db=db)


@router.patch("/{scan_id}/status", response_model=ScanResponse)
def update_scan_status(
    scan_id: int,
    payload: ScanStatusUpdateRequest,
    user: User = Depends(require_roles({Role.admin, Role.analyst})),
    db: Session = Depends(get_db),
) -> ScanResponse:
    if payload.status != "reviewed":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported status transition")
    scan = ScanningService.mark_reviewed(db=db, user_id=user.id, scan_id=scan_id)
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


@router.get("/kpi/summary", response_model=KpiSummary)
def get_kpi_summary(
    _: User = Depends(require_roles({Role.admin, Role.analyst, Role.viewer})),
    db: Session = Depends(get_db),
) -> KpiSummary:
    return VulnerabilityService.build_kpi_summary(db=db)
