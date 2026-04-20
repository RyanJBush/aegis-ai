from pydantic import BaseModel, EmailStr

from app.models.user import Role


class UserRead(BaseModel):
    id: int
    email: EmailStr
    role: Role


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: Role = Role.viewer
