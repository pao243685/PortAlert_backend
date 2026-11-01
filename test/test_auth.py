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