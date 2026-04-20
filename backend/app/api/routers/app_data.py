from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.scan import Scan
from app.models.user import User
from app.models.vulnerability import Vulnerability

router = APIRouter()


@router.get("/dashboard")
def get_dashboard(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    active_scans = db.query(func.count(Scan.id)).scalar() or 0
    open_vulns = db.query(func.count(Vulnerability.id)).filter(Vulnerability.status == "open").scalar() or 0
    return {
        "summary": {
            "active_scans": active_scans,
            "open_vulnerabilities": open_vulns,
            "critical_alerts": 0,
        },
        "message": f"Dashboard data for {user.email}",
    }
