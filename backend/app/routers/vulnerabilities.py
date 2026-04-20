from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.deps import get_db, require_roles
from app.models import User, Vulnerability
from app.schemas import VulnerabilityResponse

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    return db.query(Vulnerability).order_by(Vulnerability.created_at.desc()).all()


@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
def get_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin", "analyst")),
):
    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if not vulnerability:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return vulnerability
