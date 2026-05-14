from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_workspace_id, require_roles
from app.db.session import get_db
from app.models.user import Role, User
from app.schemas.vulnerability import (
    CVEMatch,
    RemediationTemplate,

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
from app.services.cve_enrichment import CVEEnrichmentService
import json
from pathlib import Path

REMEDIATION_TEMPLATES = json.loads(Path("backend/app/data/remediation_templates.json").read_text()) if Path("backend/app/data/remediation_templates.json").exists() else {}


def _to_read(v):
    template = REMEDIATION_TEMPLATES.get(v.rule_key)
    cves = CVEEnrichmentService.find_matches(v.title, v.affected_endpoint)
    return VulnerabilityRead(
        id=v.id, scan_id=v.scan_id, rule_key=v.rule_key, severity=v.severity, confidence=v.confidence, reason_code=v.reason_code,
        owasp_category=v.owasp_category, cwe_id=v.cwe_id, title=v.title, description=v.description, affected_endpoint=v.affected_endpoint,
        evidence=v.evidence, example_request=v.example_request, example_response=v.example_response, remediation=v.remediation,
        remediation_template=RemediationTemplate.model_validate(template) if template else None,
        secure_example=v.secure_example, dedupe_key=v.dedupe_key, is_suppressed=v.is_suppressed, status=v.status, assigned_owner=v.assigned_owner, notes=v.notes, created_at=v.created_at,
        cve_matches=[CVEMatch.model_validate(c.model_dump() if hasattr(c, "model_dump") else c) for c in cves],
    )

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
    return [_to_read(v) for v in vulns]


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
    return _to_read(vuln)


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
    return _to_read(vuln)


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
