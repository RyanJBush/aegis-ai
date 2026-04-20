from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db, require_roles
from app.models import Scan, User, Vulnerability
from app.schemas import ScanCreate, ScanResponse
from app.services import run_scan

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    findings = run_scan(payload.content)
    scan = Scan(
        target=payload.target,
        status="completed",
        summary=f"{len(findings)} finding(s)",
        created_by=current_user.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    for finding in findings:
        vuln = Vulnerability(scan_id=scan.id, **finding)
        db.add(vuln)
    db.commit()
    db.refresh(scan)

    return scan


@router.get("/scan/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if current_user.role not in {"admin", "analyst"} and scan.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not allowed to access this scan",
        )

    return scan
