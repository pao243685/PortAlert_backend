from datetime import datetime, timedelta, timezone


def test_enroll_devuelve_api_key(registrar, crear_host):
    host = crear_host(registrar())
    assert "." in host["api_key"]


def test_token_de_vinculacion_es_de_un_solo_uso(client, registrar):
    headers = registrar()
    token = client.post("/hosts/enroll-token", headers=headers).json()["enroll_token"]
    body = {"enroll_token": token, "name": "pc", "os_family": "windows"}
    assert client.post("/hosts/enroll", json=body).status_code == 201
    assert client.post("/hosts/enroll", json=body).status_code == 401


def test_token_invalido(client):
    body = {"enroll_token": "x" * 40, "name": "pc", "os_family": "linux"}
    assert client.post("/hosts/enroll", json=body).status_code == 401


def test_token_vencido(client, registrar):
    from app.core.database import SessionLocal
    from app.models import User

    headers = registrar()
    token = client.post("/hosts/enroll-token", headers=headers).json()["enroll_token"]
    with SessionLocal() as db:
        u = db.query(User).one()
        u.enroll_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    body = {"enroll_token": token, "name": "pc", "os_family": "linux"}
    assert client.post("/hosts/enroll", json=body).status_code == 401


def test_un_usuario_solo_puede_tener_un_host(client, registrar, crear_host):
    headers = registrar()
    crear_host(headers, "laptop")
    assert client.post("/hosts/enroll-token", headers=headers).status_code == 409


def test_pedir_token_requiere_sesion(client):
    assert client.post("/hosts/enroll-token").status_code == 401


def test_host_recien_vinculado_no_tiene_score_hasta_su_primer_reporte(registrar, crear_host):
    # el front usa score == null para distinguir "vinculado" de "primer reporte recibido"
    assert crear_host(registrar())["score"] is None