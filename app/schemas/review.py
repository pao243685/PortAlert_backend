from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.host import HostOut


class FindingOut(BaseModel):
    title: str
    severity: str
    confidence: str
    port: int | None
    protocol: str | None
    service: str | None
    bind_address: str | None
    process: str | None
    exe_path: str | None
    username: str | None
    package: str | None
    recommendation: str
    can_mark_normal: bool  # solo los hallazgos de puerto se pueden marcar como normales
    is_normal: bool


class ReviewOut(BaseModel):
    host: HostOut
    report_id: int
    received_at: datetime
    score: int | None
    review_completed: bool
    counts: dict[str, int]
    findings: list[FindingOut]


class NormalIn(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(min_length=1, max_length=10)
    exe_path: str | None = Field(default=None, max_length=1024)
    normal: bool
