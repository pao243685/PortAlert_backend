import logging
import threading
from datetime import datetime, timezone

import httpx
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import config
from app.core.database import SessionLocal
from app.core.security import as_utc, hash_telegram_token
from app.models import Alert, AlertStatus, Host, User
from app.schemas.alert import reference_of

log = logging.getLogger("portalert.telegram")

API = "https://api.telegram.org"

MSG_INICIO = (
    "Hola, soy el bot de PortAlert. Para recibir tus alertas aquí, "
    "abre el enlace de vinculación desde la página Mi equipo de PortAlert."
)
MSG_VINCULADO = (
    "Telegram conectado. Desde ahora recibirás aquí las alertas de tu equipo."
)
MSG_ENLACE_INVALIDO = (
    "El enlace venció o ya se usó. Genera uno nuevo desde la página Mi equipo de PortAlert."
)
MSG_CHAT_EN_USO = "Este chat ya está vinculado a otra cuenta de PortAlert."
MSG_PRUEBA = "Mensaje de prueba de PortAlert. Si lo ves, las alertas llegarán a este chat."

SEVERIDAD_TEXTO = {"critica": "CRÍTICA", "alta": "ALTA", "media": "MEDIA", "baja": "BAJA"}


def configurado() -> bool:
    return bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_BOT_USERNAME)


def enlace_de_vinculacion(token: str) -> str:
    return f"https://t.me/{config.TELEGRAM_BOT_USERNAME}?start={token}"


def _url(metodo: str) -> str:
    return f"{API}/bot{config.TELEGRAM_BOT_TOKEN}/{metodo}"


def enviar_mensaje(chat_id: str, texto: str) -> bool:
    try:
        r = httpx.post(
            _url("sendMessage"),
            json={"chat_id": chat_id, "text": texto, "disable_web_page_preview": True},
            timeout=10,
        )
    except httpx.HTTPError as e:
        log.warning("sendMessage falló: %s", type(e).__name__)
        return False
    if r.status_code != 200:
        log.warning("sendMessage respondió %s", r.status_code)
        return False
    return True


def _vincular(db: Session, chat_id: str, token: str) -> None:
    ahora = datetime.now(timezone.utc)
    huella = hash_telegram_token(token)
    user = db.scalar(select(User).where(User.telegram_link_token_hash == huella))
    if (
        not user
        or user.telegram_link_expires_at is None
        or as_utc(user.telegram_link_expires_at) <= ahora
    ):
        enviar_mensaje(chat_id, MSG_ENLACE_INVALIDO)
        return

    hosts = select(Host.id).where(Host.user_id == user.id)
    try:
        reclamado = db.execute(
            update(User)
            .where(User.id == user.id, User.telegram_link_token_hash == huella)
            .values(
                telegram_chat_id=chat_id,
                telegram_link_token_hash=None,
                telegram_link_expires_at=None,
            )
        )
        if reclamado.rowcount != 1:
            db.rollback()
            enviar_mensaje(chat_id, MSG_ENLACE_INVALIDO)
            return
        db.execute(
            update(Alert)
            .where(Alert.host_id.in_(hosts), Alert.notified_at.is_(None))
            .values(notified_at=ahora)
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        enviar_mensaje(chat_id, MSG_CHAT_EN_USO)
        return
    enviar_mensaje(chat_id, MSG_VINCULADO)


def procesar_update(db: Session, data: dict) -> None:
    mensaje = data.get("message") or {}
    chat = mensaje.get("chat") or {}
    texto = (mensaje.get("text") or "").strip()
    if chat.get("type") != "private" or "id" not in chat:
        return
    partes = texto.split(maxsplit=1)
    if not partes or partes[0].split("@")[0] != "/start":
        return
    chat_id = str(chat["id"])
    if len(partes) == 2:
        _vincular(db, chat_id, partes[1].strip())
    else:
        enviar_mensaje(chat_id, MSG_INICIO)


def _texto_alerta(alerta: Alert, host: Host) -> str:
    sev = SEVERIDAD_TEXTO.get(alerta.severity.value, alerta.severity.value.upper())
    return (
        f"PortAlert · {reference_of(alerta.id)} · {sev}\n"
        f"{alerta.title}\n\n"
        f"Equipo: {host.name}\n"
        f"Nivel de confianza: {alerta.confidence}\n\n"
        f"Ver el detalle: {config.FRONTEND_URL}/alertas/{alerta.id}\n\n"
        "Es un indicio, no una confirmación."
    )


def notificar_pendientes(host_id: int) -> None:
    if not configurado():
        return
    with SessionLocal() as db:
        host = db.get(Host, host_id)
        user = db.get(User, host.user_id) if host else None
        if not user or not user.telegram_chat_id:
            return
        pendientes = db.scalars(
            select(Alert)
            .where(
                Alert.host_id == host_id,
                Alert.status == AlertStatus.nueva,
                Alert.notified_at.is_(None),
            )
            .order_by(Alert.id)
        ).all()
        for alerta in pendientes:
            if not enviar_mensaje(user.telegram_chat_id, _texto_alerta(alerta, host)):
                break
            alerta.notified_at = datetime.now(timezone.utc)
            db.commit()


def _bucle_polling(parar: threading.Event) -> None:
    offset = None
    with httpx.Client(timeout=40) as cliente:
        try:
            cliente.post(_url("deleteWebhook"))
        except httpx.HTTPError:
            pass
        while not parar.is_set():
            params = {"timeout": 30, "allowed_updates": '["message"]'}
            if offset is not None:
                params["offset"] = offset
            try:
                r = cliente.get(_url("getUpdates"), params=params)
                if r.status_code != 200:
                    parar.wait(5)
                    continue
                for u in r.json().get("result", []):
                    offset = u["update_id"] + 1
                    try:
                        with SessionLocal() as db:
                            procesar_update(db, u)
                    except Exception as e:
                        log.warning("update no procesado: %s", type(e).__name__)
            except (httpx.HTTPError, ValueError, KeyError) as e:
                log.warning("getUpdates falló: %s", type(e).__name__)
                parar.wait(5)


def iniciar_polling() -> threading.Event | None:
    if not configurado() or config.TELEGRAM_WEBHOOK_SECRET:
        return None
    parar = threading.Event()
    threading.Thread(target=_bucle_polling, args=(parar,), daemon=True).start()
    return parar
