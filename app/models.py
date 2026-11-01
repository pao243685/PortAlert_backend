from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # Vinculación del agente: se guarda el hash del token, nunca el token.
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
    # unique=True: un usuario tiene un solo dispositivo (relación 1:1 del diagrama)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True
    )
    name: Mapped[str] = mapped_column(String(100))
    os_family: Mapped[str] = mapped_column(String(20))
    os_version: Mapped[str | None] = mapped_column(String(100))
    api_key_prefix: Mapped[str] = mapped_column(String(12), unique=True, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(255))
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    score: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="host")