"""Primera revisión: hallazgos del primer reporte, marcar "es normal en este equipo" y terminar."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Baseline, Host, Report, User
from app.schemas.host import HostOut
from app.schemas.review import FindingOut, NormalIn, ReviewOut
from app.services.analyzer import clave_normal, hallazgos_de_reporte

router = APIRouter(prefix="/review", tags=["review"])

SEVERIDADES = ("critica", "alta", "media", "baja")
CONFIANZAS = ("alta", "media", "baja")
MAX_NORMALES = 500


def _host(user: User, db: Session) -> Host:
    host = db.scalar(select(Host).where(Host.user_id == user.id))
    if not host:
        raise HTTPException(404, "Aún no hay un equipo vinculado")
    return host


@router.get("", response_model=ReviewOut)
def get_review(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    host = _host(user, db)
    primero = db.scalar(
        select(Report).where(Report.host_id == host.id).order_by(Report.id.asc()).limit(1)
    )
    if not primero:
        raise HTTPException(404, "Todavía no hay un primer reporte")

    normales = {
        (b.port, b.protocol, b.exe_path)
        for b in db.scalars(select(Baseline).where(Baseline.host_id == host.id))
    }
    hallazgos = sorted(
        hallazgos_de_reporte(db, primero),
        key=lambda h: (SEVERIDADES.index(h.severidad), CONFIANZAS.index(h.confianza), h.puerto or 0),
    )
    findings = []
    for h in hallazgos:
        clave = clave_normal(h)
        findings.append(
            FindingOut(
                title=h.titulo,
                severity=h.severidad,
                confidence=h.confianza,
                port=h.puerto,
                protocol=h.protocolo,
                service=h.servicio,
                bind_address=h.bind_address,
                process=h.proceso,
                exe_path=h.exe_path,
                username=h.usuario,
                package=h.paquete,
                recommendation=h.recomendacion,
                can_mark_normal=clave is not None,
                is_normal=clave in normales if clave else False,
            )
        )
    return ReviewOut(
        host=HostOut.model_validate(host),
        report_id=primero.id,
        received_at=primero.received_at,
        score=primero.score,
        review_completed=host.review_completed_at is not None,
        counts={s: sum(1 for f in findings if f.severity == s) for s in SEVERIDADES},
        findings=findings,
    )


@router.put("/normal", status_code=204)
def set_normal(
    data: NormalIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    host = _host(user, db)
    protocolo, ruta = data.protocol.lower(), data.exe_path or ""
    existente = db.scalar(
        select(Baseline).where(
            Baseline.host_id == host.id,
            Baseline.port == data.port,
            Baseline.protocol == protocolo,
            Baseline.exe_path == ruta,
        )
    )
    if data.normal and not existente:
        total = db.scalar(select(func.count(Baseline.id)).where(Baseline.host_id == host.id))
        if total >= MAX_NORMALES:
            raise HTTPException(409, "Ya marcaste demasiados elementos como normales")
        db.add(Baseline(host_id=host.id, port=data.port, protocol=protocolo, exe_path=ruta))
    elif not data.normal and existente:
        db.delete(existente)
    db.commit()


@router.post("/complete", response_model=HostOut)
def complete_review(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    host = _host(user, db)
    if host.review_completed_at is None:
        host.review_completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(host)
    return host
