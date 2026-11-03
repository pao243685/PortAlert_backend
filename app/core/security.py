import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from cryptography.fernet import Fernet

from app.core.config import (
    ACCESS_TOKEN_MINUTES,
    MFA_TOKEN_MINUTES,
    SECRET_KEY,
    TOTP_ENCRYPTION_KEY,
)

_fernet = Fernet(TOTP_ENCRYPTION_KEY.encode())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def generate_api_key() -> tuple[str, str]:
    prefix = secrets.token_hex(6)
    key = f"{prefix}.{secrets.token_urlsafe(32)}"
    return key, prefix


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(key: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_api_key(key), hashed)


# --- token de vinculacion del agente (un solo uso, solo se guarda su hash) ---
def generate_enroll_token() -> str:
    return secrets.token_urlsafe(32)


def hash_enroll_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --- cifrado de totp_secret: lo hace la aplicacion, la BD solo ve texto cifrado ---
def encrypt_secret(plain: str) -> str:
    return _fernet.encrypt(plain.encode()).decode()


def decrypt_secret(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()


# --- JWT: el claim "typ" separa el token de sesion del token de segundo factor ---
def _create_token(user_id: int, typ: str, minutes: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode(
        {"sub": str(user_id), "typ": typ, "exp": exp}, SECRET_KEY, algorithm="HS256"
    )


def _decode_token(token: str, typ: str) -> int | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("typ") != typ:
            return None
        return int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        return None


def create_access_token(user_id: int) -> str:
    return _create_token(user_id, "access", ACCESS_TOKEN_MINUTES)


def decode_access_token(token: str) -> int | None:
    return _decode_token(token, "access")


def create_mfa_token(user_id: int) -> str:
    return _create_token(user_id, "mfa", MFA_TOKEN_MINUTES)


def decode_mfa_token(token: str) -> int | None:
    return _decode_token(token, "mfa")


def as_utc(dt: datetime) -> datetime:
    """SQLite devuelve datetimes sin zona; Postgres con zona. Unifica."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
