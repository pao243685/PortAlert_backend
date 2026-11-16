import hmac
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.core import config
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import as_utc, generate_telegram_token, hash_telegram_token
from app.models import User
from app.schemas.telegram import TelegramLinkOut, TelegramStatusOut
from app.services import telegram

router = APIRouter(prefix="/telegram", tags=["telegram"])


def _estado(user: User) -> str:
    if user.telegram_chat_id:
        return "linked"
    if user.telegram_link_token_hash and user.telegram_link_expires_at:
        vigente = as_utc(user.telegram_link_expires_at) > datetime.now(timezone.utc)
        return "pending" if vigente else "expired"
    return "none"


def _requerir_bot() -> None:
    if not telegram.configurado():
        raise HTTPException(503, "Las notificaciones por Telegram no están disponibles todavía")


@router.get("/status", response_model=TelegramStatusOut)
def status(user: User = Depends(get_current_user)):
    estado = _estado(user)
    return TelegramStatusOut(
        state=estado,
        available=telegram.configurado(),
        expires_at=user.telegram_link_expires_at if estado in ("pending", "expired") else None,
    )


@router.post("/link", response_model=TelegramLinkOut, status_code=201)
def create_link(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _requerir_bot()
    if user.telegram_chat_id:
        raise HTTPException(409, "Ya tienes Telegram conectado")
    token = generate_telegram_token()
    expires = datetime.now(timezone.utc) + timedelta(minutes=config.TELEGRAM_LINK_MINUTES)
    user.telegram_link_token_hash = hash_telegram_token(token)
    user.telegram_link_expires_at = expires
    db.commit()
    return TelegramLinkOut(url=telegram.enlace_de_vinculacion(token), expires_at=expires)


@router.post("/test", status_code=204)
def send_test(user: User = Depends(get_current_user)):
    _requerir_bot()
    if not user.telegram_chat_id:
        raise HTTPException(409, "Primero conecta Telegram")
    if not telegram.enviar_mensaje(user.telegram_chat_id, telegram.MSG_PRUEBA):
        raise HTTPException(502, "No pudimos enviar el mensaje de prueba. Inténtalo de nuevo.")


@router.delete("/link", status_code=204)
def remove_link(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.telegram_chat_id = None
    user.telegram_link_token_hash = None
    user.telegram_link_expires_at = None
    db.commit()


@router.post("/webhook")
def webhook(
    data: dict,
    x_telegram_bot_api_secret_token: str = Header(default=""),
    db: Session = Depends(get_db),
):
    secreto = config.TELEGRAM_WEBHOOK_SECRET
    if not secreto:
        raise HTTPException(404, "No encontrado")
    if not hmac.compare_digest(x_telegram_bot_api_secret_token, secreto):
        raise HTTPException(403, "Secreto inválido")
    telegram.procesar_update(db, data)
    return {"ok": True}
