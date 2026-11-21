"""La API usa SQLAlchemy con parámetros enlazados. Estos tests lo comprueban con cargas típicas y vigilan que
nadie introduzca SQL armado a mano."""
import pathlib
import re

import pytest

PW = "Zorro-Azul-47!"
CARGAS = ["' OR '1'='1", "' OR 1=1 --", "a@correo.com'--", "'; DROP TABLE users; --", "\" OR \"\"=\"", "1; SELECT pg_sleep(5)"]


def _usuarios_en_la_base():
    from app.core.database import SessionLocal
    from app.models import User

    with SessionLocal() as db:
        return db.query(User).count()


@pytest.mark.parametrize("carga", CARGAS)
def test_login_con_carga_en_correo_y_contrasena(client, registrar, carga):
    registrar()
    assert client.post("/auth/login", data={"username": carga, "password": PW}).status_code == 401
    assert client.post("/auth/login", data={"username": "a@correo.com", "password": carga}).status_code == 401
    assert _usuarios_en_la_base() == 1  # la tabla sigue ahí y sin filas extra


@pytest.mark.parametrize("carga", CARGAS)
def test_registro_con_carga_en_el_correo_se_rechaza(client, carga):
    r = client.post("/auth/register", json={"email": carga, "password": PW})
    assert r.status_code == 422 and _usuarios_en_la_base() == 0


@pytest.mark.parametrize("carga", CARGAS)
def test_filtros_y_rutas_con_carga_dan_422_o_404_nunca_500(client, registrar, carga):
    headers = registrar()
    assert client.get("/alerts", params={"status": carga}, headers=headers).status_code == 422
    assert client.get(f"/alerts/{carga}", headers=headers).status_code in (404, 422)
    assert client.patch("/alerts/1", json={"status": carga}, headers=headers).status_code == 422
    assert client.get("/panel/score-history", params={"days": carga}, headers=headers).status_code == 422


def test_cabecera_de_api_key_con_carga(client):
    r = client.post("/reports", json={"processes": [], "ports": []}, headers={"X-API-Key": "' OR 1=1 --"})
    assert r.status_code == 401


def test_no_hay_sql_armado_a_mano_en_el_codigo():
    """Falla si aparece SQL crudo, f-strings dentro de execute() o text() fuera de la lista permitida."""
    raiz = pathlib.Path(__file__).resolve().parent.parent / "app"
    permitido = {("routers/health.py", 'text("SELECT 1")')}  # consulta constante, sin datos del usuario
    malos = []
    for f in raiz.rglob("*.py"):
        rel = f.relative_to(raiz).as_posix()
        codigo = f.read_text(encoding="utf-8")
        for m in re.finditer(r"\btext\(\s*[^)]*\)", codigo):
            if (rel, m.group(0)) not in permitido:
                malos.append((rel, m.group(0)))
        if re.search(r"execute\(\s*f?[\"']", codigo) or re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(\{|%s|\"\s*\+|\+\s*\")", codigo):
            malos.append((rel, "SQL armado con cadenas"))
    assert not malos, f"Revisa estos usos (riesgo de inyección SQL): {malos}"
