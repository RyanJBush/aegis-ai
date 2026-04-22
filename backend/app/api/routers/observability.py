from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_workspace_id, require_roles
from app.db.session import get_db
from app.models.user import Role, User
from app.schemas.observability import AuditLogRead, RuleChangeCreate, RuleChangeRead, ScanMetricsSummary
from app.services.observability_service import ObservabilityService

router = APIRouter()


@router.get("/audit-logs", response_model=list[AuditLogRead])
def list_audit_logs(
    action: str | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst})),
    db: Session = Depends(get_db),
) -> list[AuditLogRead]:
    return ObservabilityService.list_audit_logs(
        db=db,
        workspace_id=workspace_id,
        action=action,
        entity_type=entity_type,
        limit=limit,
        offset=offset,
    )


@router.get("/scan-metrics", response_model=ScanMetricsSummary)
def get_scan_metrics(
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> ScanMetricsSummary:
    return ObservabilityService.get_scan_metrics(db=db, workspace_id=workspace_id)


@router.post("/rule-history", response_model=RuleChangeRead)
def create_rule_change(
    payload: RuleChangeCreate,
    workspace_id: int = Depends(get_workspace_id),
    user: User = Depends(require_roles({Role.admin, Role.security_analyst})),
    db: Session = Depends(get_db),
) -> RuleChangeRead:
    return ObservabilityService.create_rule_change(
        db=db,
        workspace_id=workspace_id,
        actor_user_id=user.id,
        payload=payload,
    )


@router.get("/rule-history", response_model=list[RuleChangeRead])
def list_rule_history(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> list[RuleChangeRead]:
    return ObservabilityService.list_rule_changes(db=db, workspace_id=workspace_id, limit=limit, offset=offset)
