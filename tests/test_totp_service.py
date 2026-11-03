import pyotp

from app.core.database import SessionLocal
from app.core.security import encrypt_secret
from app.models import User
from app.services import totp


def test_provisioning_uri_lleva_el_emisor():
    uri = totp.provisioning_uri(totp.new_secret(), "a@correo.com")
    assert uri.startswith("otpauth://totp/") and "issuer=PortAlert" in uri


def test_matching_step_tolera_un_paso_de_desfase():
    secret = totp.new_secret()
    gen = pyotp.TOTP(secret)
    ahora = 1_700_000_000
    paso = ahora // 30
    assert totp.matching_step(secret, gen.at(ahora), ahora) == paso
    assert totp.matching_step(secret, gen.at(ahora - 30), ahora) == paso - 1
    assert totp.matching_step(secret, gen.at(ahora + 30), ahora) == paso + 1
    assert totp.matching_step(secret, gen.at(ahora + 90), ahora) is None
    validos = {gen.at(ahora + d) for d in (-30, 0, 30)}
    malo = next(c for c in ("000000", "111111") if c not in validos)
    assert totp.matching_step(secret, malo, ahora) is None


def test_verify_and_consume_bloquea_el_replay():
    secret = totp.new_secret()
    with SessionLocal() as db:
        user = User(email="a@correo.com", password_hash="x", totp_secret=encrypt_secret(secret))
        db.add(user)
        db.commit()
        codigo = pyotp.TOTP(secret).now()
        assert totp.verify_and_consume(db, user, codigo) is True
        assert totp.verify_and_consume(db, user, codigo) is False
