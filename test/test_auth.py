def test_registro(client):
    r = client.post(
        "/auth/register", json={"email": "A@Correo.com", "password": "Clave12345"}
    )
    assert r.status_code == 201
    assert r.json()["email"] == "a@correo.com"
    assert "password" not in r.json() and "password_hash" not in r.json()


def test_correo_duplicado(client):
    body = {"email": "a@correo.com", "password": "Clave12345"}
    assert client.post("/auth/register", json=body).status_code == 201
    assert client.post("/auth/register", json=body).status_code == 409


def test_clave_corta_se_rechaza(client):
    r = client.post(
        "/auth/register", json={"email": "a@correo.com", "password": "corta"}
    )
    assert r.status_code == 422


def test_correo_invalido_se_rechaza(client):
    r = client.post(
        "/auth/register", json={"email": "no-es-correo", "password": "Clave12345"}
    )
    assert r.status_code == 422

def test_registro_y_login(client):
    client.post("/auth/register", json={"email": "a@correo.com", "password": "Clave12345"})
    r = client.post(
        "/auth/login", data={"username": "a@correo.com", "password": "Clave12345"}
    )
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"


def test_login_con_clave_incorrecta(client, registrar):
    registrar("a@correo.com")
    r = client.post(
        "/auth/login", data={"username": "a@correo.com", "password": "otra-clave-1"}
    )
    assert r.status_code == 401


def test_login_con_correo_inexistente(client):
    r = client.post(
        "/auth/login", data={"username": "nadie@correo.com", "password": "Clave12345"}
    )
    assert r.status_code == 401


def test_me_con_token(client, registrar):
    r = client.get("/auth/me", headers=registrar())
    assert r.status_code == 200 and r.json()["email"] == "a@correo.com"


def test_me_sin_token(client):
    assert client.get("/auth/me").status_code == 401


def test_me_con_token_falso(client):
    r = client.get("/auth/me", headers={"Authorization": "Bearer no-es-un-jwt"})
    assert r.status_code == 401