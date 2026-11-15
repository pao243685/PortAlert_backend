from tests.test_analyzer import VACIO, reporte_telnet
from tests.test_review import TELNET_Y_SSH


def test_panel_sin_equipo_o_sin_reportes(client, registrar, crear_host):
    headers = registrar()
    assert client.get("/panel", headers=headers).status_code == 404
    crear_host(headers)
    p = client.get("/panel", headers=headers).json()
    assert p["latest"] is None and p["agent_status"] is None and p["review_completed"] is False
    assert client.get("/panel/score-history", headers=headers).json()["points"] == []


def test_panel_con_reportes(client, registrar, crear_host, enviar):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, VACIO)
    enviar(host, reporte_telnet())
    p = client.get("/panel", headers=headers).json()
    assert p["agent_status"] == "conectado" and p["latest"]["seconds_ago"] < 60
    assert p["first_score"] == 100 and p["latest"]["score"] == 70
    assert p["new_total"] == 1 and p["new_alerts"]["critica"] == 1
    assert len(p["recent_alerts"]) == 1 and p["recent_alerts"][0]["reference"].startswith("PA-")


def test_panel_sin_conexion_tras_cinco_minutos(client, registrar, crear_host, enviar):
    from datetime import datetime, timedelta, timezone

    from app.core.database import SessionLocal
    from app.models import Report

    headers = registrar()
    enviar(crear_host(headers), VACIO)
    with SessionLocal() as db:
        r = db.query(Report).one()
        r.received_at = datetime.now(timezone.utc) - timedelta(minutes=12)
        db.commit()
    p = client.get("/panel", headers=headers).json()
    assert p["agent_status"] == "sin_conexion" and p["latest"]["seconds_ago"] >= 700


def test_historial_del_puntaje(client, registrar, crear_host, enviar):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, VACIO)
    enviar(host, reporte_telnet())
    for dias in (7, 30):
        h = client.get(f"/panel/score-history?days={dias}", headers=headers).json()
        assert h["days"] == dias and len(h["points"]) == 1  # un punto por día: el último reporte
        assert h["points"][0]["score"] == 70 and h["current_score"] == 70 and h["first_score"] == 100
    assert client.get("/panel/score-history?days=15", headers=headers).status_code == 422


def test_puertos_sin_reportes(client, registrar, crear_host):
    headers = registrar()
    crear_host(headers)
    d = client.get("/ports", headers=headers).json()
    assert d["report_id"] is None and d["ports"] == [] and d["total"] == 0


def test_puertos_del_ultimo_reporte(client, registrar, crear_host, enviar):
    headers = registrar()
    enviar(crear_host(headers), TELNET_Y_SSH)
    d = client.get("/ports", headers=headers).json()
    assert d["total"] == 2 and d["with_risk"] == 2 and d["normal"] == 0
    telnet = next(p for p in d["ports"] if p["port"] == 23)
    assert telnet["severity"] == "critica" and telnet["scope"] == "all" and telnet["process"] == "telnetd"
    assert telnet["pid"] == 50 and telnet["package"] == "telnetd" and telnet["recommendation"]


def test_puertos_marcados_como_normal(client, registrar, crear_host, enviar):
    headers = registrar()
    enviar(crear_host(headers), TELNET_Y_SSH)
    client.put("/review/normal", json={"port": 22, "protocol": "tcp", "exe_path": "/usr/sbin/sshd", "normal": True}, headers=headers)
    d = client.get("/ports", headers=headers).json()
    assert d["normal"] == 1 and next(p for p in d["ports"] if p["port"] == 22)["is_normal"] is True


def test_puerto_que_mejora_respecto_del_primer_reporte(client, registrar, crear_host, enviar):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, reporte_telnet("0.0.0.0"))
    enviar(host, reporte_telnet("127.0.0.1"))
    d = client.get("/ports", headers=headers).json()
    p = d["ports"][0]
    assert p["scope"] == "local" and p["severity"] is None
    assert d["improvements"][0]["port"] == 23 and d["improvements"][0]["bind_address"] == "127.0.0.1"
