import hmac
import time

import pyotp
from sqlalchemy import or_, update
from sqlalchemy.orm import Session

from app.core.security import decrypt_secret
from app.models import User

STEP_SECONDS = 30
VENTANA = 1  # tolera +-1 paso (30 s) por desfase de reloj


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret, interval=STEP_SECONDS).provisioning_uri(
        name=email, issuer_name="PortAlert"
    )


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """Devuelve el paso (time-step) al que corresponde el codigo, o None."""
    actual = int((time.time() if now is None else now) // STEP_SECONDS)
    totp = pyotp.TOTP(secret, interval=STEP_SECONDS)
    encontrado = None
    for step in range(actual - VENTANA, actual + VENTANA + 1):
        if hmac.compare_digest(totp.generate_otp(step), code):
            encontrado = step
    return encontrado


def verify_and_consume(db: Session, user: User, code: str) -> bool:
    """Valida el codigo y marca su paso como usado (anti-replay).

    El UPDATE condicional es atomico: si dos peticiones llegan con el mismo
    codigo, solo una logra avanzar totp_last_used_step.
    """
    if not user.totp_secret:
        return False
    step = matching_step(decrypt_secret(user.totp_secret), code)
    if step is None:
        return False
    res = db.execute(
        update(User)
        .where(
            User.id == user.id,
            or_(User.totp_last_used_step.is_(None), User.totp_last_used_step < step),
        )
        .values(totp_last_used_step=step)
    )
    db.commit()
    return res.rowcount == 1
