from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_workspace_id, require_roles
from app.db.session import get_db
from app.models.user import Role, User
from app.schemas.ai import FindingAIInsight, ScanExecutiveSummary
from app.services.ai_analysis_service import AIAnalysisService

router = APIRouter()


@router.get("/findings/{vuln_id}/insight", response_model=FindingAIInsight)
def get_finding_ai_insight(
    vuln_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> FindingAIInsight:
    insight = AIAnalysisService.generate_finding_insight(db=db, workspace_id=workspace_id, vuln_id=vuln_id)
    if not insight:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return insight


@router.get("/scans/{scan_id}/executive-summary", response_model=ScanExecutiveSummary)
def get_scan_executive_summary(
    scan_id: int,
    workspace_id: int = Depends(get_workspace_id),
    _: User = Depends(require_roles({Role.admin, Role.security_analyst, Role.developer, Role.viewer})),
    db: Session = Depends(get_db),
) -> ScanExecutiveSummary:
    summary = AIAnalysisService.generate_scan_executive_summary(db=db, workspace_id=workspace_id, scan_id=scan_id)
    if not summary:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return summary
