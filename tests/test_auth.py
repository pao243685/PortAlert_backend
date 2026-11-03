def test_registro_y_login(client):
    r = client.post(
        "/auth/register", json={"email": "a@correo.com", "password": "Clave12345"}
    )
    assert r.status_code == 201
    assert r.json()["email"] == "a@correo.com"
    r = client.post(
        "/auth/login", data={"username": "a@correo.com", "password": "Clave12345"}
    )
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"


def test_correo_duplicado(client, registrar):
    registrar("a@correo.com")
    r = client.post(
        "/auth/register", json={"email": "a@correo.com", "password": "Clave12345"}
    )
    assert r.status_code == 409


def test_login_con_clave_incorrecta(client, registrar):
    registrar("a@correo.com")
    r = client.post(
        "/auth/login", data={"username": "a@correo.com", "password": "otra-clave-1"}
    )
    assert r.status_code == 401


def test_me_sin_token(client):
    assert client.get("/auth/me").status_code == 401


def test_clave_corta_se_rechaza(client):
    r = client.post(
        "/auth/register", json={"email": "a@correo.com", "password": "corta"}
    )
    assert r.status_code == 422

# ---------------- 2FA (TOTP) ----------------
import time

import pyotp


def _activar_2fa(client, headers):
    secret = client.post("/auth/totp/setup", headers=headers).json()["secret"]
    totp = pyotp.TOTP(secret)
    ahora = time.time()
    r = client.post("/auth/totp/enable", json={"code": totp.at(ahora)}, headers=headers)
    assert r.status_code == 200 and r.json()["totp_enabled"] is True
    return totp, ahora


def test_totp_secret_se_guarda_cifrado(client, registrar):
    from app.core.database import SessionLocal
    from app.models import User

    headers = registrar()
    secret = client.post("/auth/totp/setup", headers=headers).json()["secret"]
    with SessionLocal() as db:
        guardado = db.query(User).one().totp_secret
    assert guardado and secret not in guardado


def test_login_con_2fa_pide_codigo(client, registrar):
    headers = registrar()
    totp, ahora = _activar_2fa(client, headers)
    r = client.post("/auth/login", data={"username": "a@correo.com", "password": "Clave12345"})
    assert r.status_code == 200
    assert r.json()["mfa_required"] is True and r.json()["access_token"] is None
    mfa = r.json()["mfa_token"]
    r = client.post("/auth/login/totp", json={"mfa_token": mfa, "code": totp.at(ahora + 30)})
    assert r.status_code == 200 and r.json()["access_token"]


def test_codigo_totp_no_se_puede_reutilizar(client, registrar):
    headers = registrar()
    totp, ahora = _activar_2fa(client, headers)
    login = lambda: client.post(
        "/auth/login", data={"username": "a@correo.com", "password": "Clave12345"}
    ).json()["mfa_token"]
    codigo = totp.at(ahora + 30)
    assert client.post("/auth/login/totp", json={"mfa_token": login(), "code": codigo}).status_code == 200
    # mismo codigo otra vez (replay) y el codigo anterior ya consumido en enable
    assert client.post("/auth/login/totp", json={"mfa_token": login(), "code": codigo}).status_code == 401
    assert client.post("/auth/login/totp", json={"mfa_token": login(), "code": totp.at(ahora)}).status_code == 401


def test_mfa_token_no_sirve_como_sesion(client, registrar):
    headers = registrar()
    _activar_2fa(client, headers)
    mfa = client.post(
        "/auth/login", data={"username": "a@correo.com", "password": "Clave12345"}
    ).json()["mfa_token"]
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {mfa}"})
    assert r.status_code == 401


def test_codigo_totp_incorrecto(client, registrar):
    headers = registrar()
    client.post("/auth/totp/setup", headers=headers)
    r = client.post("/auth/totp/enable", json={"code": "000000"}, headers=headers)
    assert r.status_code == 400
