from datetime import datetime

from pydantic import BaseModel, computed_field

from app.models import AlertStatus, EventType, Severity
from app.schemas.host import HostOut

EVENT_LABEL = {
    EventType.puerto_nuevo: "Puerto nuevo",
    EventType.proceso_sospechoso: "Proceso sospechoso",
}


def reference_of(alert_id: int) -> str:
    return f"PA-{alert_id:03d}"


class AlertOut(BaseModel):
    id: int
    host_id: int
    port: int | None
    title: str
    message: str
    severity: Severity
    status: AlertStatus
    confidence: str
    event_type: EventType | None = None
    created_at: datetime
    notified_at: datetime | None = None
    model_config = {"from_attributes": True}

    @computed_field
    @property
    def reference(self) -> str:
        return reference_of(self.id)

    @computed_field
    @property
    def event_label(self) -> str | None:
        return EVENT_LABEL.get(self.event_type) if self.event_type else None


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    # Al ignorar: "Es normal en este equipo. No volver a avisarme de este puerto como nuevo."
    mark_normal: bool = False


class AlertDetailOut(AlertOut):
    host: HostOut
    description: str
    protocol: str | None
    service: str | None
    bind_address: str | None
    exe_path: str | None
    username: str | None
    package: str | None
    confidence_note: str
    recommendation: str
    can_mark_normal: bool
    reputation: str | None = None
