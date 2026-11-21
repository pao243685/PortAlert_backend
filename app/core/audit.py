"""Registro de eventos de seguridad. Nunca se escriben contraseñas, tokens ni códigos."""
import hashlib
import logging

log = logging.getLogger("portalert.security")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)
    log.propagate = False


def email_tag(email: str) -> str:
    """Huella corta del correo: sirve para correlacionar intentos sin guardar el correo en claro."""
    return hashlib.sha256(email.lower().encode()).hexdigest()[:10]


def event(name: str, level: int = logging.INFO, **fields) -> None:
    log.log(level, "%s %s", name, " ".join(f"{k}={v}" for k, v in fields.items()))
