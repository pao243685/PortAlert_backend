import pytest

from app.core.passwords import problems

OK = "Zorro-Azul-47!"


def _registrar(client, password, email="nuevo@correo.com"):
    return client.post("/auth/register", json={"email": email, "password": password})


def test_contrasena_valida(client):
    assert _registrar(client, OK).status_code == 201


@pytest.mark.parametrize(
    "password,falta",
    [
        ("Ab1!", "al menos 8 caracteres"),
        ("zorro-azul-47!", "mayúscula"),
        ("ZORRO-AZUL-47!", "minúscula"),
        ("Zorro-Azul-aa!", "número"),
        ("ZorroAzul4747", "carácter especial"),
        ("Password1!", "común"),
        ("Clave12345!", "común"),
        ("12345678", "mayúscula"),
        (" Zorro-Azul-47!", "espacios"),
    ],
)
def test_contrasenas_rechazadas(client, password, falta):
    r = _registrar(client, password)
    assert r.status_code == 422
    assert falta in r.json()["detail"][0]["msg"]


def test_rechaza_las_que_exceden_72_bytes(client):
    larga = "Aa1!" + "ñ" * 40  # 44 caracteres pero 84 bytes: bcrypt la truncaría
    assert len(larga) < 72 and len(larga.encode()) > 72
    r = _registrar(client, larga)
    assert r.status_code == 422 and "72 bytes" in r.json()["detail"][0]["msg"]


def test_rechaza_contrasena_que_contiene_el_correo(client):
    r = _registrar(client, "Lucia2026-Seguro!", email="lucia@correo.com")
    assert r.status_code == 422 and "correo" in r.json()["detail"][0]["msg"]


def test_el_mensaje_lista_todo_lo_que_falta(client):
    msg = _registrar(client, "abc").json()["detail"][0]["msg"]
    for esperado in ("8 caracteres", "mayúscula", "número", "carácter especial"):
        assert esperado in msg


def test_problems_devuelve_vacio_si_cumple():
    assert problems(OK, "otra@correo.com") == []


def test_login_con_contrasena_gigante_no_da_500(client):
    r = client.post("/auth/login", data={"username": "a@correo.com", "password": "ñ" * 10_000})
    assert r.status_code == 401


def test_login_sigue_aceptando_contrasenas_antiguas_que_no_cumplen_la_politica(client):
    # cuentas creadas antes de la política: la política solo se exige al registrarse
    from app.core.database import SessionLocal
    from app.core.security import hash_password
    from app.models import User

    with SessionLocal() as db:
        db.add(User(email="vieja@correo.com", password_hash=hash_password("clave-simple")))
        db.commit()
    r = client.post("/auth/login", data={"username": "vieja@correo.com", "password": "clave-simple"})
    assert r.status_code == 200
