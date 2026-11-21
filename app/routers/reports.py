from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.core.config import VIRUSTOTAL_API_KEY
from app.core.database import get_db
from app.core.deps import get_current_host
from app.core.ratelimit import hit_key
from app.models import Host
from app.schemas.report import ReportIn, ReportOut
from app.services import telegram
from app.services.reports import ingest_report
from app.services.virustotal import consultar_y_reanalizar

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("", response_model=ReportOut, status_code=201)
def submit_report(
    data: ReportIn,
    background: BackgroundTasks,
    host: Host = Depends(get_current_host),
    db: Session = Depends(get_db),
):
    hit_key("reports", host.id)  # un agente legítimo manda ~1 por minuto: 120/min es de sobra
    report = ingest_report(db, host, data)
    host.last_seen = datetime.now(timezone.utc)
    db.commit()
    db.refresh(report)
    if telegram.configurado():
        background.add_task(telegram.notificar_pendientes, host.id)
    if VIRUSTOTAL_API_KEY:
        background.add_task(consultar_y_reanalizar, report.id)
    return report
