from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.session import get_db
from app.models.user import Role, User
from app.schemas.vulnerability import VulnerabilityRead, VulnerabilityReport, VulnerabilityWorkflowUpdate
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter()


@router.get("", response_model=list[VulnerabilityRead])
def list_vulnerabilities(
    _: User = Depends(require_roles({Role.admin, Role.analyst, Role.viewer})),
    db: Session = Depends(get_db),
) -> list[VulnerabilityRead]:
    vulns = VulnerabilityService.list_vulnerabilities(db=db)
    return [VulnerabilityRead.model_validate(v) for v in vulns]


@router.get("/reports/summary", response_model=VulnerabilityReport)
def get_report(
    _: User = Depends(require_roles({Role.admin, Role.analyst})),
    db: Session = Depends(get_db),
) -> VulnerabilityReport:
    return VulnerabilityService.build_report(db=db)


@router.get("/{vuln_id}", response_model=VulnerabilityRead)
def get_vulnerability(
    vuln_id: int,
    _: User = Depends(require_roles({Role.admin, Role.analyst, Role.viewer})),
    db: Session = Depends(get_db),
) -> VulnerabilityRead:
    vuln = VulnerabilityService.get_vulnerability(db=db, vuln_id=vuln_id)
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return VulnerabilityRead.model_validate(vuln)


@router.patch("/{vuln_id}/workflow", response_model=VulnerabilityRead)
def update_vulnerability_workflow(
    vuln_id: int,
    payload: VulnerabilityWorkflowUpdate,
    user: User = Depends(require_roles({Role.admin, Role.analyst})),
    db: Session = Depends(get_db),
) -> VulnerabilityRead:
    vuln = VulnerabilityService.update_workflow(
        db=db,
        vuln_id=vuln_id,
        actor_user_id=user.id,
        payload=payload,
    )
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return VulnerabilityRead.model_validate(vuln)
