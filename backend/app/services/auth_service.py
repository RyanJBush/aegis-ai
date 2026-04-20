import logging

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_password_hash, verify_password
from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest, Token

logger = logging.getLogger(__name__)


class AuthService:
    @staticmethod
    def register(db: Session, payload: RegisterRequest) -> User:
        existing = db.query(User).filter(User.email == payload.email).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

        user = User(
            email=payload.email.lower().strip(),
            hashed_password=get_password_hash(payload.password),
            role=payload.role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("Created user account", extra={"email": user.email, "role": user.role.value})
        return user

    @staticmethod
    def login(db: Session, payload: LoginRequest) -> Token:
        user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
        if not user or not verify_password(payload.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        token = create_access_token(subject=user.email, user_id=user.id, role=user.role)
        logger.info("User login success", extra={"user_id": user.id, "email": user.email})
        return Token(access_token=token)
