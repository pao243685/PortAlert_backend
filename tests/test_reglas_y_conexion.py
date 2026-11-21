from datetime import datetime, timedelta, timezone

import pytest

from app.core import config
from app.core.database import SessionLocal
from app.models import Alert, Host, Report
from app.services import telegram
from tests.test_analyzer import VACIO, con_primer_reporte

SECRETO = "secreto-de-pruebas"


@pytest.fixture
def enviados(monkeypatch):
    lista = []
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: lista.append((c, t)) or True)
    return lista


def _vincular_telegram(client, headers, chat_id=555):
    token = client.post("/telegram/link", headers=headers).json()["url"].split("start=")[1]
    data = {"update_id": 1, "message": {"chat": {"id": chat_id, "type": "private"}, "text": f"/start {token}"}}
    client.post("/telegram/webhook", json=data, headers={"X-Telegram-Bot-Api-Secret-Token": SECRETO})


def _servicio(nombre, usuario, puertos):
    return {
        "processes": [{"pid": 10 + i, "name": nombre, "username": usuario} for i, _ in enumerate(puertos)],
        "ports": [
            {"port": p, "protocol": "tcp", "bind_address": "0.0.0.0", "pid": 10 + i}
            for i, p in enumerate(puertos)
        ],
    }


def _envejecer_reportes(minutos):
    with SessionLocal() as db:
        db.query(Report).update({"received_at": datetime.now(timezone.utc) - timedelta(minutes=minutos)})
        db.commit()


def test_servicio_de_windows_como_system_no_genera_alerta(client, registrar, crear_host, enviar):
    headers = registrar()
    host = con_primer_reporte(enviar, crear_host(headers))
    r = enviar(host, _servicio("svchost.exe", "NT AUTHORITY\\SYSTEM", [49664, 49665, 49666]))
    assert r.json()["score"] == 100
    assert client.get("/alerts", headers=headers).json() == []


def test_servicio_linux_como_root_en_puerto_alto_sigue_siendo_baja(client, registrar, crear_host, enviar):
    headers = registrar()
    host = con_primer_reporte(enviar, crear_host(headers))
    enviar(host, _servicio("miapp", "root", [9000]))
    alertas = client.get("/alerts", headers=headers).json()
    assert len(alertas) == 1 and alertas[0]["severity"] == "baja"


def test_muchos_hallazgos_bajos_no_hunden_el_puntaje(client, registrar, crear_host, enviar):
    headers = registrar()
    host = con_primer_reporte(enviar, crear_host(headers))
    r = enviar(host, _servicio("miapp", "root", list(range(9000, 9030))))
    assert r.json()["score"] == 80


def test_una_alerta_baja_se_envia_a_telegram(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    _vincular_telegram(client, headers)
    enviados.clear()
    enviar(host, VACIO)
    enviar(host, _servicio("miapp", "root", [9000]))
    assert len(enviados) == 1 and "BAJA" in enviados[0][1]


def test_el_minimo_de_severidad_se_puede_subir(client, registrar, crear_host, enviar, enviados, monkeypatch):
    monkeypatch.setattr(config, "TELEGRAM_MIN_SEVERITY", "media")
    headers = registrar()
    host = crear_host(headers)
    _vincular_telegram(client, headers)
    enviados.clear()
    enviar(host, VACIO)
    enviar(host, _servicio("miapp", "root", [9000]))
    assert enviados == []
    with SessionLocal() as db:
        assert db.query(Alert).one().notified_at is None


def test_aviso_cuando_el_agente_deja_de_reportar(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    _vincular_telegram(client, headers)
    enviar(host, VACIO)
    enviados.clear()
    _envejecer_reportes(10)
    telegram.revisar_conexion()
    assert len(enviados) == 1
    assert enviados[0][0] == "555" and "sin conexión" in enviados[0][1] and "laptop" in enviados[0][1]
    assert "sudo systemctl restart portalert-agent" in enviados[0][1]
    telegram.revisar_conexion()
    assert len(enviados) == 1


def test_no_avisa_si_el_agente_reporta_a_tiempo(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    _vincular_telegram(client, headers)
    enviar(host, VACIO)
    enviados.clear()
    _envejecer_reportes(2)
    telegram.revisar_conexion()
    assert enviados == []


def test_avisa_cuando_el_agente_vuelve(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    _vincular_telegram(client, headers)
    enviar(host, VACIO)
    _envejecer_reportes(10)
    telegram.revisar_conexion()
    enviados.clear()
    enviar(host, VACIO)
    telegram.revisar_conexion()
    assert len(enviados) == 1 and "de nuevo en línea" in enviados[0][1]
    with SessionLocal() as db:
        assert db.query(Host).one().offline_notified_at is None
    telegram.revisar_conexion()
    assert len(enviados) == 1


def test_sin_telegram_no_hay_aviso_de_desconexion(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, VACIO)
    _envejecer_reportes(10)
    telegram.revisar_conexion()
    assert enviados == []


def test_si_telegram_falla_el_aviso_de_desconexion_se_reintenta(client, registrar, crear_host, enviar, monkeypatch):
    headers = registrar()
    host = crear_host(headers)
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: True)
    _vincular_telegram(client, headers)
    enviar(host, VACIO)
    _envejecer_reportes(10)
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: False)
    telegram.revisar_conexion()
    with SessionLocal() as db:
        assert db.query(Host).one().offline_notified_at is None
    reintentos = []
    monkeypatch.setattr(telegram, "enviar_mensaje", lambda c, t: reintentos.append(t) or True)
    telegram.revisar_conexion()
    assert len(reintentos) == 1


def test_el_aviso_de_desconexion_en_windows_trae_el_comando_de_powershell(client, registrar, crear_host, enviar, enviados):
    headers = registrar()
    host = crear_host(headers)
    _vincular_telegram(client, headers)
    enviar(host, VACIO)
    with SessionLocal() as db:
        db.query(Host).update({"os_family": "windows"})
        db.commit()
    enviados.clear()
    _envejecer_reportes(10)
    telegram.revisar_conexion()
    assert "PowerShell como administrador" in enviados[0][1]
    assert "Start-ScheduledTask -TaskName PortAlertAgent" in enviados[0][1]
