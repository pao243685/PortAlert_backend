from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Alert, AlertStatus, Baseline, Host, Report, User
from app.schemas.alert import AlertDetailOut, AlertOut, AlertStatusUpdate
from app.schemas.host import HostOut
from app.services.analyzer import clave_normal, encontrar_hallazgo

router = APIRouter(prefix="/alerts", tags=["alerts"])

NOTA_CONFIANZA = {
    "alta": "Alta. Lo observado coincide claramente con la regla que lo detectó.",
    "media": "Media. El indicio es coherente, pero el contexto disponible es limitado.",
    "baja": "Baja. Es una señal débil: conviene confirmarla antes de actuar.",
}


def _own_alert(db: Session, user: User, alert_id: int) -> Alert:
    alert = db.scalar(
        select(Alert).join(Host).where(Alert.id == alert_id, Host.user_id == user.id)
    )
    if not alert:
        raise HTTPException(404, "Alerta no encontrada")
    return alert


def _hallazgo(db: Session, alert: Alert):
    """Reconstruye el hallazgo con todos sus datos a partir del reporte que lo originó."""
    report = db.get(Report, alert.report_id) if alert.report_id else db.scalar(
        select(Report).where(Report.host_id == alert.host_id).order_by(Report.id.desc()).limit(1)
    )
    if not report or alert.rule_id is None:
        return None
    return encontrar_hallazgo(db, report, alert.rule_id, alert.port, alert.title)


@router.get("", response_model=list[AlertOut])
def list_alerts(
    status: AlertStatus | None = None,
    host_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = (
        select(Alert)
        .join(Host)
        .where(Host.user_id == user.id)
        .order_by(Alert.created_at.desc(), Alert.id.desc())
    )
    if status:
        query = query.where(Alert.status == status)
    if host_id:
        query = query.where(Alert.host_id == host_id)
    return db.scalars(query).all()


@router.get("/{alert_id}", response_model=AlertDetailOut)
def get_alert(
    alert_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    alert = _own_alert(db, user, alert_id)
    h = _hallazgo(db, alert)
    base = AlertOut.model_validate(alert).model_dump(exclude={"reference", "event_label"})
    return AlertDetailOut(
        **base,
        host=HostOut.model_validate(alert.host),
        description=f"{h.detalle}." if h else alert.message.split("\n\n")[0],
        protocol=h.protocolo if h else None,
        service=h.servicio if h else None,
        bind_address=h.bind_address if h else None,
        exe_path=h.exe_path if h else None,
        username=h.usuario if h else None,
        package=h.paquete if h else None,
        confidence_note=NOTA_CONFIANZA.get(alert.confidence, NOTA_CONFIANZA["media"]),
        recommendation=h.recomendacion if h else "",
        can_mark_normal=bool(h and clave_normal(h)),
        reputation=next(
            (
                c.removeprefix("Reputación de la huella: ")
                for c in (h.contexto if h else [])
                if c.startswith("Reputación de la huella:")
            ),
            None,
        ),
    )


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: int,
    data: AlertStatusUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    alert = _own_alert(db, user, alert_id)
    if data.mark_normal:
        if data.status != AlertStatus.ignorada:
            raise HTTPException(400, "Solo se puede marcar como normal al ignorar la alerta")
        h = _hallazgo(db, alert)
        clave = clave_normal(h) if h else None
        if not clave:
            raise HTTPException(400, "Esta alerta no se puede marcar como normal")
        puerto, protocolo, ruta = clave
        existe = db.scalar(
            select(Baseline.id).where(
                Baseline.host_id == alert.host_id,
                Baseline.port == puerto,
                Baseline.protocol == protocolo,
                Baseline.exe_path == ruta,
            )
        )
        if not existe:
            db.add(Baseline(host_id=alert.host_id, port=puerto, protocol=protocolo, exe_path=ruta))
    alert.status = data.status
    db.commit()
    db.refresh(alert)
    return alert
