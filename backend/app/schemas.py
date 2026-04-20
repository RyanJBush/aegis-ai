from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

RoleType = Literal["user", "analyst", "admin"]
SeverityType = Literal["low", "medium", "high", "critical"]


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    role: RoleType
    created_at: datetime


class AppDataCreate(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=5000)


class AppDataResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    title: str
    content: str
    created_at: datetime


class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=20000)


class VulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    title: str
    severity: SeverityType
    details: str
    explanation: str
    created_at: datetime


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    status: str
    summary: str
    created_by: int
    created_at: datetime
    vulnerabilities: list[VulnerabilityResponse]
