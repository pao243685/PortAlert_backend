from app.core.constants import MAX_BYTES_REPORTE

REPORTE_LIMPIO = {
    "processes": [{"pid": 1, "name": "sshd"}],
    "ports": [{"port": 22, "protocol": "tcp", "bind_address": "127.0.0.1", "pid": 1}],
}


def test_reporte_con_api_key_valida(registrar, crear_host, enviar):
    host = crear_host(registrar())
    r = enviar(host, REPORTE_LIMPIO)
    assert r.status_code == 201
    assert r.json()["score"] == 100


def test_reporte_actualiza_el_host(client, registrar, crear_host, enviar):
    headers = registrar()
    host = crear_host(headers)
    assert client.get("/hosts", headers=headers).json()[0]["score"] is None
    enviar(host, REPORTE_LIMPIO)
    assert client.get("/hosts", headers=headers).json()[0]["score"] == 100


def test_reporte_sin_api_key(client):
    assert client.post("/reports", json=REPORTE_LIMPIO).status_code == 422


def test_reporte_con_api_key_falsa(client):
    r = client.post("/reports", json=REPORTE_LIMPIO, headers={"X-API-Key": "abc123.falsa"})
    assert r.status_code == 401


def test_reporte_con_demasiados_puertos(registrar, crear_host, enviar):
    host = crear_host(registrar())
    puertos = [{"port": 8000, "protocol": "tcp", "bind_address": "127.0.0.1"} for _ in range(2001)]
    assert enviar(host, {"processes": [], "ports": puertos}).status_code == 422


def test_reporte_excede_tamano(client, registrar, crear_host):
    host = crear_host(registrar())
    r = client.post(
        "/reports",
        content=b"x" * (MAX_BYTES_REPORTE + 1),
        headers={"X-API-Key": host["api_key"], "Content-Type": "application/json"},
    )
    assert r.status_code == 413
