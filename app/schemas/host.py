from datetime import datetime

from pydantic import BaseModel, Field


class EnrollTokenOut(BaseModel):
    enroll_token: str
    expires_at: datetime


class EnrollIn(BaseModel):
    enroll_token: str = Field(min_length=20, max_length=200)
    name: str = Field(min_length=1, max_length=100)
    os_family: str = Field(min_length=1, max_length=20)
    os_version: str | None = Field(default=None, max_length=100)


class HostOut(BaseModel):
    id: int
    name: str
    os_family: str
    os_version: str | None
    last_seen: datetime
    score: int | None
    model_config = {"from_attributes": True}


class HostCreated(HostOut):
    api_key: str