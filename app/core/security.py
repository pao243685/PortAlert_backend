from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.core.config import ACCESS_TOKEN_MINUTES, SECRET_KEY


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# El claim typ separa el token de sesión de otros tokens que se agreguen después
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