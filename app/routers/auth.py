import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit, config
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import (
    create_access_token,
    create_mfa_token,
    decode_mfa_token,
    encrypt_secret,
    hash_password,
    verify_dummy,
    verify_password,
)
from app.core.ratelimit import LIMITES, client_ip, limiter, rate_limit, too_many
from app.models import User
from app.schemas.auth import (
    LoginOut,
    LoginTotpIn,
    TotpCode,
    TotpSetupOut,
    UserCreate,
    UserOut,
)
from app.services import totp

router = APIRouter(prefix="/auth", tags=["auth"])


def _ip(request: Request) -> str:
    return client_ip(request.headers, request.client.host if request.client else None)


def _bloqueo(clave: str, nombre: str) -> None:
    """Si esa clave ya acumuló demasiados fallos recientes, corta con 429 antes de hacer nada más."""
    if not config.RATE_LIMIT_ENABLED:
        return
    limite, ventana = LIMITES[nombre]
    espera = limiter.blocked(clave, limite, ventana)
    if espera:
        raise too_many(espera)


@router.post("/register", response_model=UserOut, status_code=201, dependencies=[Depends(rate_limit("register"))])
def register(request: Request, data: UserCreate, db: Session = Depends(get_db)):
    email = data.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "El correo ya está registrado")
    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.event("registro", usuario=user.id, ip=_ip(request))
    return user


@router.post("/login", response_model=LoginOut, dependencies=[Depends(rate_limit("login"))])
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = form.username.lower()
    ip = _ip(request)
    k_ip, k_cuenta = f"login-fallos-ip:{email}:{ip}", f"login-fallos-cuenta:{email}"
    _bloqueo(k_ip, "login-fallos-ip")        # 5 fallos / 15 min desde la misma IP para ese correo
    _bloqueo(k_cuenta, "login-fallos-cuenta")  # 20 fallos / 15 min contra ese correo desde cualquier IP

    user = db.scalar(select(User).where(User.email == email))
    if user:
        correcto = verify_password(form.password, user.password_hash)
    else:
        verify_dummy(form.password)  # mismo tiempo de respuesta exista o no el correo
        correcto = False
    if not correcto:
        limiter.fail(k_ip)
        limiter.fail(k_cuenta)
        audit.event("login_fallido", logging.WARNING, correo=audit.email_tag(email), ip=ip)
        raise HTTPException(401, "Credenciales incorrectas")
    limiter.clear(k_ip)
    audit.event("login_ok", usuario=user.id, ip=ip, mfa=user.totp_enabled)
    if user.totp_enabled:
        return LoginOut(mfa_required=True, mfa_token=create_mfa_token(user.id))
    return LoginOut(access_token=create_access_token(user.id))


@router.post("/login/totp", response_model=LoginOut, dependencies=[Depends(rate_limit("totp"))])
def login_totp(request: Request, data: LoginTotpIn, db: Session = Depends(get_db)):
    user_id = decode_mfa_token(data.mfa_token)
    clave = f"totp-fallos:{user_id}"
    if user_id:
        _bloqueo(clave, "totp-fallos")  # el código tiene solo 6 dígitos: se corta la adivinación a los 5 fallos
    user = db.get(User, user_id) if user_id else None
    if not user or not user.totp_enabled or not totp.verify_and_consume(db, user, data.code):
        if user_id:
            limiter.fail(clave)
        audit.event("totp_fallido", logging.WARNING, usuario=user_id, ip=_ip(request))
        raise HTTPException(401, "Código inválido o ya usado")
    limiter.clear(clave)
    audit.event("login_totp_ok", usuario=user.id, ip=_ip(request))
    return LoginOut(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.post("/totp/setup", response_model=TotpSetupOut, dependencies=[Depends(rate_limit("totp"))])
def totp_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.totp_enabled:
        raise HTTPException(409, "El 2FA ya está activado")
    secret = totp.new_secret()
    user.totp_secret = encrypt_secret(secret)  # se cifra aquí, en la aplicación
    user.totp_last_used_step = None
    db.commit()
    # El secreto en claro solo se devuelve en esta respuesta (para el QR).
    return TotpSetupOut(secret=secret, otpauth_uri=totp.provisioning_uri(secret, user.email))


@router.post("/totp/enable", response_model=UserOut, dependencies=[Depends(rate_limit("totp"))])
def totp_enable(
    request: Request, data: TotpCode, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    if user.totp_enabled or not user.totp_secret:
        raise HTTPException(409, "Primero inicia la configuración del 2FA")
    clave = f"totp-fallos:{user.id}"
    _bloqueo(clave, "totp-fallos")
    if not totp.verify_and_consume(db, user, data.code):
        limiter.fail(clave)
        raise HTTPException(400, "Código inválido")
    limiter.clear(clave)
    user.totp_enabled = True
    db.commit()
    audit.event("2fa_activado", usuario=user.id, ip=_ip(request))
    db.refresh(user)
    return user
