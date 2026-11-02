from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import ENROLL_TOKEN_MINUTES
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import (
    as_utc,
    generate_api_key,
    generate_enroll_token,
    hash_api_key,
    hash_enroll_token,
)
from app.models import Host, User
from app.schemas.host import EnrollIn, EnrollTokenOut, HostCreated, HostOut

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.post("/enroll-token", response_model=EnrollTokenOut, status_code=201)
def create_enroll_token(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """El usuario (ya con sesión) pide un token para vincular su dispositivo."""
    if db.scalar(select(Host.id).where(Host.user_id == user.id)):
        raise HTTPException(409, "Ya tienes un dispositivo vinculado")
    token = generate_enroll_token()
    expires = datetime.now(timezone.utc) + timedelta(minutes=ENROLL_TOKEN_MINUTES)
    user.enroll_token_hash = hash_enroll_token(token)
    user.enroll_expires_at = expires
    user.enroll_used_at = None
    db.commit()
    return EnrollTokenOut(enroll_token=token, expires_at=expires)


@router.post("/enroll", response_model=HostCreated, status_code=201)
def enroll(data: EnrollIn, db: Session = Depends(get_db)):
    """Lo llama el agente (sin sesión): canjea el token por una API key."""
    now = datetime.now(timezone.utc)
    user = db.scalar(
        select(User).where(User.enroll_token_hash == hash_enroll_token(data.enroll_token))
    )
    if (
        not user
        or user.enroll_used_at is not None
        or user.enroll_expires_at is None
        or as_utc(user.enroll_expires_at) <= now
    ):
        raise HTTPException(401, "Token de vinculación inválido o vencido")

    # Consumir el token de forma atómica: solo una petición puede ganar.
    claimed = db.execute(
        update(User)
        .where(User.id == user.id, User.enroll_used_at.is_(None))
        .values(enroll_used_at=now)
    )
    if claimed.rowcount != 1:
        db.rollback()
        raise HTTPException(401, "Token de vinculación inválido o vencido")

    key, prefix = generate_api_key()
    host = Host(
        user_id=user.id,
        name=data.name,
        os_family=data.os_family.lower(),
        os_version=data.os_version,
        api_key_prefix=prefix,
        api_key_hash=hash_api_key(key),
    )
    db.add(host)
    try:
        db.commit()  # confirma el consumo del token y el host juntos
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Este usuario ya tiene un dispositivo vinculado")
    db.refresh(host)
    return {**HostOut.model_validate(host).model_dump(), "api_key": key}


@router.get("", response_model=list[HostOut])
def list_hosts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(select(Host).where(Host.user_id == user.id)).all()


@router.delete("/{host_id}", status_code=204)
def delete_host(
    host_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    host = db.scalar(select(Host).where(Host.id == host_id, Host.user_id == user.id))
    if not host:
        raise HTTPException(404, "Host no encontrado")
    db.delete(host)
    db.commit()