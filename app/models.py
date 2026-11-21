import enum
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Severity(str, enum.Enum):
    baja = "baja"
    media = "media"
    alta = "alta"
    critica = "critica"


class AlertStatus(str, enum.Enum):
    nueva = "nueva"
    atendida = "atendida"
    ignorada = "ignorada"


class EventType(str, enum.Enum):
    puerto_nuevo = "puerto_nuevo"
    proceso_sospechoso = "proceso_sospechoso"


SeverityType = Enum(Severity, name="severity")
EventTypeType = Enum(EventType, name="event_type")
AlertStatusType = Enum(AlertStatus, name="alert_status")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # Cifrado en la aplicacion (Fernet, ver core/security.py); la BD solo guarda
    # el texto cifrado, por eso es String(255) y no el secreto base32 de 32 chars.
    totp_secret: Mapped[str | None] = mapped_column(String(255))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Ultimo time-step (unix // 30) aceptado: un codigo con paso <= a este es replay.
    totp_last_used_step: Mapped[int | None] = mapped_column(BigInteger)
    telegram_chat_id: Mapped[str | None] = mapped_column(String(64), unique=True)
    telegram_link_token_hash: Mapped[str | None] = mapped_column(
        String(64), unique=True
    )
    telegram_link_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    # Vinculacion del agente: se guarda el hash del token, nunca el token.
    enroll_token_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    enroll_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enroll_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    host: Mapped["Host | None"] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    # unique=True: un usuario tiene un solo dispositivo (relacion 1:1 del diagrama)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True
    )
    name: Mapped[str] = mapped_column(String(100))
    os_family: Mapped[str] = mapped_column(String(20))
    os_version: Mapped[str | None] = mapped_column(String(100))
    api_key_prefix: Mapped[str] = mapped_column(String(12), unique=True, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(255))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    score: Mapped[int | None] = mapped_column(Integer)
    # Se llena cuando la persona pulsa "Terminar revisión" en la primera revisión.
    review_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    offline_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="host")
    baseline: Mapped[list["Baseline"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    score: Mapped[int | None] = mapped_column(Integer)

    host: Mapped["Host"] = relationship(back_populates="reports")
    ports: Mapped[list["PortEntry"]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )
    processes: Mapped[list["ProcessEntry"]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )


class ProcessEntry(Base):
    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    pid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255))
    exe_path: Mapped[str | None] = mapped_column(Text)
    username: Mapped[str | None] = mapped_column(String(100))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    package: Mapped[str | None] = mapped_column(String(200))
    exe_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    report: Mapped["Report"] = relationship(back_populates="processes")


class PortEntry(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    process_id: Mapped[int | None] = mapped_column(
        ForeignKey("processes.id", ondelete="SET NULL")
    )
    port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(10))
    bind_address: Mapped[str] = mapped_column(String(64))
    service_name: Mapped[str | None] = mapped_column(String(100))

    report: Mapped["Report"] = relationship(back_populates="ports")


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(SeverityType)
    recommendation: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[int | None] = mapped_column(
        ForeignKey("rules.id", ondelete="SET NULL")
    )
    # Reporte y proceso que originaron la alerta (para reconstruir el detalle) y su huella.
    report_id: Mapped[int | None] = mapped_column(
        ForeignKey("reports.id", ondelete="SET NULL")
    )
    process_id: Mapped[int | None] = mapped_column(
        ForeignKey("processes.id", ondelete="SET NULL")
    )
    event_type: Mapped[EventType | None] = mapped_column(EventTypeType)
    fingerprint: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(SeverityType)
    status: Mapped[AlertStatus] = mapped_column(
        AlertStatusType, default=AlertStatus.nueva, index=True
    )
    confidence: Mapped[str] = mapped_column(
        String(10), default="media", server_default="media"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    host: Mapped["Host"] = relationship(back_populates="alerts")

class FileReputation(Base):
    __tablename__ = "file_reputations"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(12))
    malicious: Mapped[int] = mapped_column(Integer, default=0)
    suspicious: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

class Baseline(Base):
    """Lo que la persona marcó como "Es normal en este equipo": no vuelve a generar alertas."""

    __tablename__ = "baseline"
    __table_args__ = (UniqueConstraint("host_id", "port", "protocol", "exe_path"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10))
    exe_path: Mapped[str] = mapped_column(Text, default="")  # "" si no se conoce el ejecutable

    host: Mapped["Host"] = relationship(back_populates="baseline")
