from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=255)
    payload: str = Field(min_length=1, max_length=20000)


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    status: str
    created_at: datetime
    vulnerabilities_found: int
