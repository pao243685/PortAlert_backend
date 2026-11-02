from datetime import datetime

from pydantic import BaseModel, Field

from app.core.constants import MAX_ELEMENTOS_REPORTE


class ProcessIn(BaseModel):
    pid: int
    name: str = Field(max_length=255)
    exe_path: str | None = Field(default=None, max_length=1024)
    username: str | None = Field(default=None, max_length=100)
    sha256: str | None = Field(default=None, min_length=64, max_length=64)
    package: str | None = Field(default=None, max_length=200)
    exe_deleted: bool = False


class PortIn(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(max_length=10)
    bind_address: str = Field(max_length=64)
    service_name: str | None = Field(default=None, max_length=100)
    pid: int | None = None


class ReportIn(BaseModel):
    processes: list[ProcessIn] = Field(default=[], max_length=MAX_ELEMENTOS_REPORTE)
    ports: list[PortIn] = Field(default=[], max_length=MAX_ELEMENTOS_REPORTE)


class ReportOut(BaseModel):
    id: int
    received_at: datetime
    score: int | None
    model_config = {"from_attributes": True}
