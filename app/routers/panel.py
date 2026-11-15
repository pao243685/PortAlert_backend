"""Panel: estado del equipo, conexión del agente, alertas nuevas e historial del puntaje."""
from datetime import datetime, time, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import as_utc
from app.models import Alert, AlertStatus, Host, Report, User
from app.schemas.alert import AlertOut
from app.schemas.host import HostOut
from app.schemas.panel import HistoryOut, LatestReport, PanelOut, ScorePoint

router = APIRouter(prefix="/panel", tags=["panel"])

CONNECTION_WINDOW = timedelta(minutes=5)
SEVERIDADES = ("critica", "alta", "media", "baja")


def _host(user: User, db: Session) -> Host:
    host = db.scalar(select(Host).where(Host.user_id == user.id))
    if not host:
        raise HTTPException(404, "Aún no hay un equipo vinculado")
    return host


@router.get("", response_model=PanelOut)
def get_panel(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    host = _host(user, db)
    latest = db.scalar(select(Report).where(Report.host_id == host.id).order_by(Report.id.desc()).limit(1))
    first = db.scalar(select(Report).where(Report.host_id == host.id).order_by(Report.id.asc()).limit(1))

    info = status = None
    if latest:
        seconds = max(0, int((datetime.now(timezone.utc) - as_utc(latest.received_at)).total_seconds()))
        info = LatestReport(received_at=latest.received_at, score=latest.score, seconds_ago=seconds)
        status = "conectado" if timedelta(seconds=seconds) < CONNECTION_WINDOW else "sin_conexion"

    rows = db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.host_id == host.id, Alert.status == AlertStatus.nueva)
        .group_by(Alert.severity)
    ).all()
    counts = {s: 0 for s in SEVERIDADES}
    for sev, n in rows:
        counts[sev.value] = n

    recent = db.scalars(
        select(Alert).where(Alert.host_id == host.id).order_by(Alert.created_at.desc(), Alert.id.desc()).limit(5)
    ).all()
    return PanelOut(
        host=HostOut.model_validate(host),
        review_completed=host.review_completed_at is not None,
        latest=info,
        first_score=first.score if first else None,
        agent_status=status,
        new_alerts=counts,
        new_total=sum(counts.values()),
        recent_alerts=[AlertOut.model_validate(a) for a in recent],
    )


@router.get("/score-history", response_model=HistoryOut)
def score_history(
    days: int = Query(7, description="7 o 30"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if days not in (7, 30):
        raise HTTPException(422, "El periodo debe ser de 7 o 30 días")
    host = _host(user, db)
    now = datetime.now(timezone.utc)
    start = datetime.combine((now - timedelta(days=days - 1)).date(), time.min, tzinfo=timezone.utc)
    first = db.execute(
        select(Report.id, Report.score).where(Report.host_id == host.id).order_by(Report.id.asc()).limit(1)
    ).first()
    rows = db.execute(
        select(Report.id, Report.received_at, Report.score)
        .where(Report.host_id == host.id, Report.received_at >= start, Report.score.is_not(None))
        .order_by(Report.id.asc())
    ).all()
    por_dia: dict[str, tuple[int, int]] = {}
    for rid, received_at, score in rows:  # el último reporte de cada día gana
        por_dia[as_utc(received_at).date().isoformat()] = (rid, score)
    puntos = [
        ScorePoint(date=d, score=score, first_review=bool(first and rid == first.id))
        for d, (rid, score) in sorted(por_dia.items())
    ]
    return HistoryOut(
        days=days,
        points=puntos,
        first_score=first.score if first else None,
        current_score=puntos[-1].score if puntos else None,
    )
