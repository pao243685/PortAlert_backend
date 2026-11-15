"""Puertos del equipo: estado del último reporte con el riesgo calculado de cada puerto."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import PUERTOS
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Baseline, Host, PortEntry, ProcessEntry, Report, User
from app.schemas.host import HostOut
from app.schemas.ports import Improvement, PortRow, PortsOut
from app.services.analyzer import hallazgos_de_reporte

router = APIRouter(prefix="/ports", tags=["ports"])

SEVERIDADES = ("critica", "alta", "media", "baja")
CONFIANZAS = ("alta", "media", "baja")
PUBLICAS = {"0.0.0.0", "::", "*"}


def _scope(bind: str) -> str:
    if bind in PUBLICAS:
        return "all"
    if bind == "::1" or bind.startswith("127."):
        return "local"
    return "specific"


def _mas_grave(actual, nuevo):
    clave = lambda h: (SEVERIDADES.index(h.severidad), CONFIANZAS.index(h.confianza))
    return nuevo if actual is None or clave(nuevo) < clave(actual) else actual


@router.get("", response_model=PortsOut)
def get_ports(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    host = db.scalar(select(Host).where(Host.user_id == user.id))
    if not host:
        raise HTTPException(404, "Aún no hay un equipo vinculado")
    latest = db.scalar(select(Report).where(Report.host_id == host.id).order_by(Report.id.desc()).limit(1))
    if not latest:
        return PortsOut(host=HostOut.model_validate(host), report_id=None, received_at=None, ports=[],
                        total=0, with_risk=0, normal=0, improvements=[])

    procesos = {p.id: p for p in db.scalars(select(ProcessEntry).where(ProcessEntry.report_id == latest.id))}
    puertos = db.scalars(select(PortEntry).where(PortEntry.report_id == latest.id).order_by(PortEntry.port)).all()
    hallazgo: dict[tuple[int, str], object] = {}
    for h in hallazgos_de_reporte(db, latest):
        if h.puerto is not None and h.protocolo:
            k = (h.puerto, h.protocolo)
            hallazgo[k] = _mas_grave(hallazgo.get(k), h)
    normales = {(b.port, b.protocol, b.exe_path) for b in db.scalars(select(Baseline).where(Baseline.host_id == host.id))}

    filas: list[PortRow] = []
    vistos: set[tuple[int, str, str]] = set()
    for p in puertos:
        proto = p.protocol.lower()
        proc = procesos.get(p.process_id) if p.process_id else None
        clave = (p.port, proto, p.bind_address)
        if clave in vistos:  # un mismo puerto escuchando en IPv4 e IPv6 con el mismo enlace
            continue
        vistos.add(clave)
        h = hallazgo.get((p.port, proto))
        info = PUERTOS.get(p.port)
        filas.append(
            PortRow(
                port=p.port, protocol=proto, bind_address=p.bind_address, scope=_scope(p.bind_address),
                service=p.service_name or (info["servicio"] if info else None),
                process=proc.name if proc else None, pid=proc.pid if proc else None,
                exe_path=proc.exe_path if proc else None, username=proc.username if proc else None,
                package=proc.package if proc else None, exe_deleted=bool(proc and proc.exe_deleted),
                severity=h.severidad if h else None, confidence=h.confianza if h else None,
                finding_title=h.titulo if h else None, recommendation=h.recomendacion if h else None,
                is_normal=(p.port, proto, (proc.exe_path if proc and proc.exe_path else "")) in normales,
            )
        )

    # Mejoras respecto del primer reporte: puertos que tenían un hallazgo y hoy ya no.
    mejoras: list[Improvement] = []
    primero = db.scalar(select(Report).where(Report.host_id == host.id).order_by(Report.id.asc()).limit(1))
    if primero and primero.id != latest.id:
        ya = set()
        for h in hallazgos_de_reporte(db, primero):
            k = (h.puerto, h.protocolo)
            if h.puerto is None or k in ya or k in hallazgo:
                continue
            fila = next((f for f in filas if (f.port, f.protocol) == k), None)
            if fila:
                ya.add(k)
                mejoras.append(Improvement(port=fila.port, protocol=fila.protocol, service=fila.service, bind_address=fila.bind_address))

    return PortsOut(
        host=HostOut.model_validate(host), report_id=latest.id, received_at=latest.received_at, ports=filas,
        total=len(filas), with_risk=sum(1 for f in filas if f.severity), normal=sum(1 for f in filas if f.is_normal),
        improvements=mejoras,
    )
