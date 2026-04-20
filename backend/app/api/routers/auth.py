from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest, Token, UserAuthResponse
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/register", response_model=UserAuthResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> UserAuthResponse:
    user = AuthService.register(db=db, payload=payload)
    return UserAuthResponse.model_validate(user)


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> Token:
    return AuthService.login(db=db, payload=payload)


@router.get("/me", response_model=UserAuthResponse)
def me(user: User = Depends(get_current_user)) -> UserAuthResponse:
    return UserAuthResponse.model_validate(user)
