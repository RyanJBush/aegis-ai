from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.user import Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.api_v1_prefix}/auth/login")


class TokenContext(BaseModel):
    user_id: int
    workspace_id: int
    email: str
    role: Role


def get_token_context(token: str = Depends(oauth2_scheme)) -> TokenContext:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        if payload.get("typ") != "access":
            raise ValueError("token type")
        user_id = int(payload.get("uid"))
        workspace_id = int(payload.get("wid"))
        email = str(payload.get("sub"))
        role = Role(payload.get("role"))
    except (JWTError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from exc
    return TokenContext(user_id=user_id, workspace_id=workspace_id, email=email, role=role)


def get_current_user(
    token_context: TokenContext = Depends(get_token_context),
    db: Session = Depends(get_db),
) -> User:
    user = (
        db.query(User)
        .filter(
            User.id == token_context.user_id,
            User.workspace_id == token_context.workspace_id,
            User.is_active.is_(True),
        )
        .first()
    )
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def get_workspace_id(
    user: User = Depends(get_current_user),
    workspace_header: int | None = Header(default=None, alias="X-Workspace-ID"),
) -> int:
    if workspace_header is not None and workspace_header != user.workspace_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-workspace access denied")
    return user.workspace_id


def require_roles(allowed_roles: set[Role]) -> Callable[[User], User]:
    def _guard(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
        return user

    return _guard
