import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.models.user import Role

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(
    subject: str,
    user_id: int,
    role: Role,
    workspace_id: int,
    expires_delta: timedelta | None = None,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode: dict[str, Any] = {
        "sub": subject,
        "uid": user_id,
        "role": role.value,
        "wid": workspace_id,
        "typ": "access",
        "exp": expire,
    }
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: int, expires_delta: timedelta | None = None) -> tuple[str, datetime]:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.refresh_token_expire_minutes)
    )
    raw_token = secrets.token_urlsafe(48)
    to_encode = {
        "sub": str(user_id),
        "uid": user_id,
        "typ": "refresh",
        "jti": secrets.token_urlsafe(16),
        "exp": expire,
    }
    signed_token = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return f"{signed_token}.{raw_token}", expire


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def password_meets_policy(password: str) -> bool:
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)
    return len(password) >= 12 and has_upper and has_lower and has_digit and has_symbol
