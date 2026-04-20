from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.session import get_db
from app.models.user import Role, User
from app.schemas.scanning import ScanRequest, ScanResponse
from app.services.scanning_service import ScanningService

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
