from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshTokenRequest, RegisterRequest, TokenPair, UserAuthResponse
from app.services.auth_service import AuthService
from app.services.rate_limit_service import RateLimitService

router = APIRouter()


@router.post("/register", response_model=UserAuthResponse)
def register(
    payload: RegisterRequest,
    _: None = Depends(RateLimitService.check_auth_rate_limit),
    db: Session = Depends(get_db),
) -> UserAuthResponse:
    user = AuthService.register(db=db, payload=payload)
    return UserAuthResponse.model_validate(user)


@router.post("/login", response_model=TokenPair)
def login(
    payload: LoginRequest,
    _: None = Depends(RateLimitService.check_auth_rate_limit),
    db: Session = Depends(get_db),
) -> TokenPair:
    return AuthService.login(db=db, payload=payload)


@router.post("/refresh", response_model=TokenPair)
def refresh(
    payload: RefreshTokenRequest,
    _: None = Depends(RateLimitService.check_auth_rate_limit),
    db: Session = Depends(get_db),
) -> TokenPair:
    return AuthService.refresh_access_token(db=db, payload=payload)


@router.post("/logout", status_code=204)
def logout(payload: RefreshTokenRequest, db: Session = Depends(get_db)) -> Response:
    AuthService.logout(db=db, payload=payload)
    return Response(status_code=204)


@router.get("/me", response_model=UserAuthResponse)
def me(user: User = Depends(get_current_user)) -> UserAuthResponse:
    return UserAuthResponse.model_validate(user)
