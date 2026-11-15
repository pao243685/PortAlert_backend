from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.host import HostOut


class PortRow(BaseModel):
    port: int
    protocol: str
    bind_address: str
    scope: Literal["all", "local", "specific"]
    service: str | None
    process: str | None
    pid: int | None
    exe_path: str | None
    username: str | None
    package: str | None
    exe_deleted: bool
    severity: str | None  # None = sin hallazgos actuales
    confidence: str | None
    finding_title: str | None
    recommendation: str | None
    is_normal: bool


class Improvement(BaseModel):
    port: int
    protocol: str
    service: str | None
    bind_address: str


class PortsOut(BaseModel):
    host: HostOut
    report_id: int | None
    received_at: datetime | None
    ports: list[PortRow]
    total: int
    with_risk: int
    normal: int
    improvements: list[Improvement]
