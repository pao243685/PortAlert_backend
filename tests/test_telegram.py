from datetime import datetime, timedelta, timezone

import pytest

from app.core.database import SessionLocal
from app.models import Alert, User
from app.services import telegram
from tests.test_analyzer import VACIO, reporte_telnet

SECRETO = "secreto-de-pruebas"


@pytest.fixture
def enviados(monkeypatch):
    lista = []

    def falso(chat_id, texto):
        lista.append((chat_id, texto))
        return True

    monkeypatch.setattr(telegram, "enviar_mensaje", falso)
    return lista


def _start(client, chat_id, token, secreto=SECRETO):
    data = {
        "update_id": 1,
        "message": {"chat": {"id": chat_id, "type": "private"}, "text": f"/start {token}"},
    }
    return client.post(
        "/telegram/webhook", json=data, headers={"X-Telegram-Bot-Api-Secret-Token": secreto}
    )


def _generar(client, headers):
    r = client.post("/telegram/link", headers=headers)
    assert r.status_code == 201
    return r.json()["url"].split("start=")[1]


def _estado(client, headers):
    return client.get("/telegram/status", headers=headers).json()["state"]


def _usuario(email="a@correo.com"):
    with SessionLocal() as db:
        return db.query(User).filter(User.email == email).one()


def test_estado_inicial_sin_vincular(client, registrar):
    headers = registrar()
    r = client.get("/telegram/status", headers=headers).json()
    assert r["state"] == "none" and r["available"] is True


def test_estado_requiere_sesion(client):
    assert client.get("/telegram/status").status_code == 401


def test_generar_enlace_deja_el_estado_en_espera(client, registrar):
    headers = registrar()
    r = client.post("/telegram/link", headers=headers).json()
    assert r["url"].startswith("https://t.me/portalert_test_bot?start=")
    assert _estado(client, headers) == "pending"


def test_el_token_se_guarda_solo_como_hash(client, registrar):
    headers = registrar()
    token = _generar(client, headers)
    assert _usuario().telegram_link_token_hash != token


def test_start_con_token_vincula_el_chat(client, registrar, enviados):
    headers = registrar()
    token = _generar(client, headers)
    assert _start(client, 555, token).status_code == 200
    u = _usuario()
    assert u.telegram_chat_id == "555"
    assert u.telegram_link_token_hash is None and u.telegram_link_expires_at is None
    assert _estado(client, headers) == "linked"
    assert enviados == [("555", telegram.MSG_VINCULADO)]


def test_el_enlace_es_de_un_solo_uso(client, registrar, enviados):
    headers = registrar()
    token = _generar(client, headers)
    _start(client, 555, token)
    _start(client, 777, token)
    assert _usuario().telegram_chat_id == "555"
    assert enviados[-1] == ("777", telegram.MSG_ENLACE_INVALIDO)


def test_enlace_vencido_no_vincula(client, registrar, enviados):
    headers = registrar()
    token = _generar(client, headers)
    with SessionLocal() as db:
        u = db.query(User).one()
        u.telegram_link_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    assert _estado(client, headers) == "expired"
    _start(client, 555, token)
    assert _usuario().telegram_chat_id is None
    assert enviados == [("555", telegram.MSG_ENLACE_INVALIDO)]


def test_token_desconocido(client, registrar, enviados):
    registrar()
    _start(client, 555, "x" * 43)
    assert enviados == [("555", telegram.MSG_ENLACE_INVALIDO)]


def test_un_chat_no_se_comparte_entre_cuentas(client, registrar, enviados):
    a = registrar("a@correo.com")
    b = registrar("b@correo.com")
    _start(client, 555, _generar(client, a))
    _start(client, 555, _generar(client, b))
    assert _usuario("b@correo.com").telegram_chat_id is None
    assert enviados[-1] == ("555", telegram.MSG_CHAT_EN_USO)


def test_start_sin_token_explica_como_vincular(client, registrar, enviados):
    registrar()
    data = {"update_id": 1, "message": {"chat": {"id": 9, "type": "private"}, "text": "/start"}}
    client.post("/telegram/webhook", json=data, headers={"X-Telegram-Bot-Api-Secret-Token": SECRETO})
    assert enviados == [("9", telegram.MSG_INICIO)]


def test_webhook_rechaza_secreto_incorrecto(client, registrar, enviados):
    headers = registrar()
    token = _generar(client, headers)
    assert _start(client, 555, token, secreto="otro").status_code == 403
    assert _usuario().telegram_chat_id is None


def test_webhook_sin_cabecera(client):
    r = client.post("/telegram/webhook", json={})
    assert r.status_code == 403


def test_no_se_genera_enlace_si_ya_esta_conectado(client, registrar, enviados):
    headers = registrar()
    _start(client, 555, _generar(client, headers))
    assert client.post("/telegram/link", headers=headers).status_code == 409


def test_mensaje_de_prueba(client, registrar, enviados):
    headers = registrar()
    _start(client, 555, _generar(client, headers))
    enviados.clear()
    assert client.post("/telegram/test", headers=headers).status_code == 204
    assert enviados == [("555", telegram.MSG_PRUEBA)]


def test_mensaje_de_prueba_sin_conectar(client, registrar, enviados):
    headers = registrar()
    assert client.post("/telegram/test", headers=headers).status_code == 409
    assert enviados == []


def test_mensaje_de_prueba_que_falla_devuelve_502(client, registrar, monkeypatch):
    headers = registrar()
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: True)
    _start(client, 555, _generar(client, headers))
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: False)
    assert client.post("/telegram/test", headers=headers).status_code == 502


def test_desconectar_limpia_el_vinculo(client, registrar, enviados):
    headers = registrar()
    _start(client, 555, _generar(client, headers))
    assert client.delete("/telegram/link", headers=headers).status_code == 204
    assert _estado(client, headers) == "none"
    assert _usuario().telegram_chat_id is None


def test_cancelar_deja_el_enlace_inservible(client, registrar, enviados):
    headers = registrar()
    token = _generar(client, headers)
    client.delete("/telegram/link", headers=headers)
    _start(client, 555, token)
    assert _usuario().telegram_chat_id is None


def test_alerta_nueva_se_envia_a_telegram(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    _start(client, 555, _generar(client, headers))
    enviados.clear()
    enviar(host, VACIO)
    enviar(host, reporte_telnet())
    assert len(enviados) == 1
    chat, texto = enviados[0]
    alerta = client.get("/alerts", headers=headers).json()[0]
    assert chat == "555"
    assert alerta["reference"] in texto and f"/alertas/{alerta['id']}" in texto
    with SessionLocal() as db:
        assert db.get(Alert, alerta["id"]).notified_at is not None


def test_la_misma_alerta_no_se_envia_dos_veces(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    _start(client, 555, _generar(client, headers))
    enviar(host, VACIO)
    enviar(host, reporte_telnet())
    enviar(host, reporte_telnet())
    alertas = [m for m in enviados if "PortAlert ·" in m[1]]
    assert len(alertas) == 1


def test_sin_telegram_la_alerta_queda_sin_notificar(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, VACIO)
    enviar(host, reporte_telnet())
    assert enviados == []
    with SessionLocal() as db:
        assert db.query(Alert).one().notified_at is None


def test_las_alertas_previas_al_vinculo_no_se_envian(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, VACIO)
    enviar(host, reporte_telnet())
    _start(client, 555, _generar(client, headers))
    enviar(host, reporte_telnet())
    assert [m for m in enviados if "PortAlert ·" in m[1]] == []


def test_si_telegram_falla_la_alerta_se_reintenta(client, registrar, crear_host, enviar, monkeypatch):
    headers = registrar()
    host = crear_host(headers)
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: True)
    _start(client, 555, _generar(client, headers))
    enviar(host, VACIO)
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: False)
    enviar(host, reporte_telnet())
    with SessionLocal() as db:
        assert db.query(Alert).one().notified_at is None
    reintentos = []
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: reintentos.append(t) or True)
    enviar(host, reporte_telnet())
    assert len(reintentos) == 1
