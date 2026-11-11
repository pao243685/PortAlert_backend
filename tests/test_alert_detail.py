from tests.test_analyzer import VACIO, reporte_telnet


def _alerta(client, registrar, crear_host, enviar):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, VACIO)  # primer reporte
    enviar(host, reporte_telnet())
    alerta = client.get("/alerts", headers=headers).json()[0]
    return headers, alerta


def test_lista_trae_referencia_y_tipo(client, registrar, crear_host, enviar):
    _, a = _alerta(client, registrar, crear_host, enviar)
    assert a["reference"] == f"PA-{a['id']:03d}"
    assert a["event_type"] == "puerto_nuevo" and a["event_label"] == "Puerto nuevo"


def test_detalle_de_alerta(client, registrar, crear_host, enviar):
    headers, a = _alerta(client, registrar, crear_host, enviar)
    r = client.get(f"/alerts/{a['id']}", headers=headers)
    assert r.status_code == 200
    d = r.json()
    assert d["port"] == 23 and d["protocol"] == "tcp" and d["service"]
    assert d["bind_address"] == "0.0.0.0" and d["can_mark_normal"] is True
    assert d["recommendation"] and d["description"].endswith(".")
    assert d["host"]["os_family"] == "linux"
    assert d["confidence_note"].startswith(d["confidence"].capitalize())


def test_detalle_de_otra_persona_es_404(client, registrar, crear_host, enviar):
    _, a = _alerta(client, registrar, crear_host, enviar)
    otro = registrar("otro@correo.com")
    assert client.get(f"/alerts/{a['id']}", headers=otro).status_code == 404


def test_ignorar_marcando_como_normal_guarda_baseline(client, registrar, crear_host, enviar):
    from app.core.database import SessionLocal
    from app.models import Baseline

    headers, a = _alerta(client, registrar, crear_host, enviar)
    r = client.patch(f"/alerts/{a['id']}", json={"status": "ignorada", "mark_normal": True}, headers=headers)
    assert r.status_code == 200 and r.json()["status"] == "ignorada"
    with SessionLocal() as db:
        fila = db.query(Baseline).one()
        assert (fila.port, fila.protocol) == (23, "tcp")


def test_marcar_como_normal_solo_al_ignorar(client, registrar, crear_host, enviar):
    headers, a = _alerta(client, registrar, crear_host, enviar)
    r = client.patch(f"/alerts/{a['id']}", json={"status": "atendida", "mark_normal": True}, headers=headers)
    assert r.status_code == 400


def test_marcar_como_atendida(client, registrar, crear_host, enviar):
    headers, a = _alerta(client, registrar, crear_host, enviar)
    r = client.patch(f"/alerts/{a['id']}", json={"status": "atendida"}, headers=headers)
    assert r.status_code == 200 and r.json()["status"] == "atendida"
