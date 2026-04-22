from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_workspace_id, require_roles
from app.db.session import get_db
from app.models.user import Role, User
from app.schemas.vulnerability import (
    FindingCommentCreate,
    FindingCommentRead,
    FindingTimeline,
    RiskAcceptanceCreate,
    RiskAcceptanceRead,
    VulnerabilityRead,
    VulnerabilityReport,
    VulnerabilityWorkflowUpdate,
)
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter()


@router.get("", response_model=list[VulnerabilityRead])
def list_vulnerabilities(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    sort_by: str = Query(default="created_at"),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> list[VulnerabilityRead]:
    vulns = VulnerabilityService.list_vulnerabilities(
        db=db,
        workspace_id=workspace_id,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return [VulnerabilityRead.model_validate(v) for v in vulns]


@router.get("/reports/summary", response_model=VulnerabilityReport)
def get_report(
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer})),
    db: Session = Depends(get_db),
) -> VulnerabilityReport:
    return VulnerabilityService.build_report(db=db, workspace_id=workspace_id)


@router.get("/{vuln_id}", response_model=VulnerabilityRead)
def get_vulnerability(
    vuln_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> VulnerabilityRead:
    vuln = VulnerabilityService.get_vulnerability(db=db, workspace_id=workspace_id, vuln_id=vuln_id)
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return VulnerabilityRead.model_validate(vuln)


@router.patch("/{vuln_id}/workflow", response_model=VulnerabilityRead)
def update_vulnerability_workflow(
    vuln_id: int,
    payload: VulnerabilityWorkflowUpdate,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst})),
    db: Session = Depends(get_db),
) -> VulnerabilityRead:
    vuln = VulnerabilityService.update_workflow(
        db=db,
        workspace_id=workspace_id,
        vuln_id=vuln_id,
        actor_user_id=user.id,
        payload=payload,
    )
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return VulnerabilityRead.model_validate(vuln)


@router.post("/{vuln_id}/comments", response_model=FindingCommentRead)
def add_comment(
    vuln_id: int,
    payload: FindingCommentCreate,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer})),
    db: Session = Depends(get_db),
) -> FindingCommentRead:
    comment = VulnerabilityService.add_comment(
        db=db,
        workspace_id=workspace_id,
        vuln_id=vuln_id,
        user_id=user.id,
        payload=payload,
    )
    if not comment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return FindingCommentRead.model_validate(comment)


@router.post("/{vuln_id}/risk-acceptance", response_model=RiskAcceptanceRead)
def create_risk_acceptance(
    vuln_id: int,
    payload: RiskAcceptanceCreate,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst})),
    db: Session = Depends(get_db),
) -> RiskAcceptanceRead:
    accepted = VulnerabilityService.create_risk_acceptance(
        db=db,
        workspace_id=workspace_id,
        vuln_id=vuln_id,
        user_id=user.id,
        payload=payload,
    )
    if not accepted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return RiskAcceptanceRead.model_validate(accepted)


@router.get("/{vuln_id}/timeline", response_model=FindingTimeline)
def get_timeline(
    vuln_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> FindingTimeline:
    timeline = VulnerabilityService.get_timeline(db=db, workspace_id=workspace_id, vuln_id=vuln_id)
    if not timeline:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return timeline
