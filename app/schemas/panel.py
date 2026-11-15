from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.alert import AlertOut
from app.schemas.host import HostOut


class LatestReport(BaseModel):
    received_at: datetime
    score: int | None
    seconds_ago: int


class PanelOut(BaseModel):
    host: HostOut
    review_completed: bool
    latest: LatestReport | None
    first_score: int | None
    # "conectado": último reporte de hace menos de 5 min; "sin_conexion": más de 5 min
    agent_status: Literal["conectado", "sin_conexion"] | None
    new_alerts: dict[str, int]
    new_total: int
    recent_alerts: list[AlertOut]


class ScorePoint(BaseModel):
    date: str  # AAAA-MM-DD (UTC): el último reporte de ese día
    score: int
    first_review: bool


class HistoryOut(BaseModel):
    days: int
    points: list[ScorePoint]
    first_score: int | None
    current_score: int | None
