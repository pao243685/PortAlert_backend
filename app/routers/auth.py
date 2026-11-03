from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import (
    create_access_token,
    create_mfa_token,
    decode_mfa_token,
    encrypt_secret,
    hash_password,
    verify_password,
)
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


@router.post("/register", response_model=UserOut, status_code=201)
def register(data: UserCreate, db: Session = Depends(get_db)):
    email = data.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "El correo ya está registrado")
    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=LoginOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == form.username.lower()))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Credenciales incorrectas")
    if user.totp_enabled:
        return LoginOut(mfa_required=True, mfa_token=create_mfa_token(user.id))
    return LoginOut(access_token=create_access_token(user.id))


@router.post("/login/totp", response_model=LoginOut)
def login_totp(data: LoginTotpIn, db: Session = Depends(get_db)):
    user_id = decode_mfa_token(data.mfa_token)
    user = db.get(User, user_id) if user_id else None
    if not user or not user.totp_enabled or not totp.verify_and_consume(db, user, data.code):
        raise HTTPException(401, "Código inválido o ya usado")
    return LoginOut(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.post("/totp/setup", response_model=TotpSetupOut)
def totp_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.totp_enabled:
        raise HTTPException(409, "El 2FA ya está activado")
    secret = totp.new_secret()
    user.totp_secret = encrypt_secret(secret)  # se cifra aquí, en la aplicación
    user.totp_last_used_step = None
    db.commit()
    # El secreto en claro solo se devuelve en esta respuesta (para el QR).
    return TotpSetupOut(secret=secret, otpauth_uri=totp.provisioning_uri(secret, user.email))


@router.post("/totp/enable", response_model=UserOut)
def totp_enable(
    data: TotpCode, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    if user.totp_enabled or not user.totp_secret:
        raise HTTPException(409, "Primero inicia la configuración del 2FA")
    if not totp.verify_and_consume(db, user, data.code):
        raise HTTPException(400, "Código inválido")
    user.totp_enabled = True
    db.commit()
    db.refresh(user)
    return user
