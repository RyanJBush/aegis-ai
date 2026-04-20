from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.deps import get_current_user, get_db
from app.models import AppData, User
from app.schemas import AppDataCreate, AppDataResponse

router = APIRouter(prefix="/api/app", tags=["app"])


@router.post("/data", response_model=AppDataResponse)
def create_app_data(
    payload: AppDataCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    record = AppData(user_id=current_user.id, title=payload.title, content=payload.content)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("/data", response_model=list[AppDataResponse])
def list_app_data(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(AppData)
    if current_user.role not in {"admin", "analyst"}:
        query = query.filter(AppData.user_id == current_user.id)
    return query.order_by(AppData.created_at.desc()).all()
