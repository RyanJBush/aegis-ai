import logging
import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    hash_refresh_token,
    password_meets_policy,
    verify_password,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.models.workspace import Workspace
from app.schemas.auth import LoginRequest, RefreshTokenRequest, RegisterRequest, TokenPair
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class AuthService:
    @staticmethod
    def register(db: Session, payload: RegisterRequest) -> User:
        existing = db.query(User).filter(User.email == payload.email).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

        if not password_meets_policy(payload.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must include upper, lower, number, symbol, and be at least 12 characters",
            )

        email = payload.email.lower().strip()
        workspace_slug = re.sub(r"[^a-z0-9]+", "-", email.split("@")[0]).strip("-")[:60] or "workspace"
        workspace = Workspace(name=f"{email} workspace", slug=f"{workspace_slug}-{int(datetime.now(timezone.utc).timestamp())}")
        db.add(workspace)
        db.flush()

        user = User(
            workspace_id=workspace.id,
            email=email,
            hashed_password=get_password_hash(payload.password),
            role=payload.role,
        )
        db.add(user)
        db.flush()
        AuditService.log(
            db,
            action="user_registered",
            entity_type="user",
            entity_id=user.id,
            actor_user_id=user.id,
            details={"email": user.email, "role": user.role.value, "workspace_id": workspace.id},
        )
        db.commit()
        db.refresh(user)
        logger.info("Created user account", extra={"email": user.email, "role": user.role.value})
        return user

    @staticmethod
    def login(db: Session, payload: LoginRequest) -> TokenPair:
        user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
        now = datetime.now(timezone.utc)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        if user.locked_until and user.locked_until > now:
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account temporarily locked")

        if not verify_password(payload.password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_failed_login_attempts:
                user.locked_until = now + timedelta(minutes=settings.account_lockout_minutes)
                AuditService.log(
                    db,
                    action="user_account_locked",
                    entity_type="user",
                    entity_id=user.id,
                    actor_user_id=user.id,
                    details={"failed_attempts": user.failed_login_attempts},
                )
            AuditService.log(
                db,
                action="user_login_failed",
                entity_type="user",
                entity_id=user.id,
                actor_user_id=user.id,
                details={"failed_attempts": user.failed_login_attempts},
            )
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        user.failed_login_attempts = 0
        user.locked_until = None
        access_token = create_access_token(
            subject=user.email,
            user_id=user.id,
            role=user.role,
            workspace_id=user.workspace_id,
        )
        refresh_token, expires_at = create_refresh_token(user_id=user.id)
        db.add(RefreshToken(user_id=user.id, token_hash=hash_refresh_token(refresh_token), expires_at=expires_at))
        AuditService.log(
            db,
            action="user_login_success",
            entity_type="user",
            entity_id=user.id,
            actor_user_id=user.id,
            details={"email": user.email, "workspace_id": user.workspace_id},
        )
        db.commit()
        logger.info("User login success", extra={"user_id": user.id, "email": user.email})
        return TokenPair(access_token=access_token, refresh_token=refresh_token)

    @staticmethod
    def refresh_access_token(db: Session, payload: RefreshTokenRequest) -> TokenPair:
        token_hash = hash_refresh_token(payload.refresh_token)
        db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash, RefreshToken.revoked.is_(False)).first()
        if not db_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        if db_token.expires_at < datetime.now(timezone.utc):
            db_token.revoked = True
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

        try:
            jwt_part = ".".join(payload.refresh_token.split(".")[:3])
            claims = jwt.decode(jwt_part, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
            if claims.get("typ") != "refresh" or int(claims.get("uid")) != db_token.user_id:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        except (JWTError, ValueError, TypeError, IndexError) as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc

        user = db.query(User).filter(User.id == db_token.user_id, User.is_active.is_(True)).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

        db_token.revoked = True
        access_token = create_access_token(
            subject=user.email,
            user_id=user.id,
            role=user.role,
            workspace_id=user.workspace_id,
        )
        new_refresh_token, expires_at = create_refresh_token(user_id=user.id)
        db.add(RefreshToken(user_id=user.id, token_hash=hash_refresh_token(new_refresh_token), expires_at=expires_at))
        AuditService.log(
            db,
            action="refresh_token_rotated",
            entity_type="user",
            entity_id=user.id,
            actor_user_id=user.id,
        )
        db.commit()
        return TokenPair(access_token=access_token, refresh_token=new_refresh_token)

    @staticmethod
    def logout(db: Session, payload: RefreshTokenRequest) -> None:
        token_hash = hash_refresh_token(payload.refresh_token)
        db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash, RefreshToken.revoked.is_(False)).first()
        if db_token:
            db_token.revoked = True
            AuditService.log(
                db,
                action="user_logout",
                entity_type="user",
                entity_id=db_token.user_id,
                actor_user_id=db_token.user_id,
            )
            db.commit()
