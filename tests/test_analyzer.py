VACIO = {"processes": [], "ports": []}


def con_primer_reporte(enviar, host):
    """El primer reporte no genera alertas (sus hallazgos van a la primera revisión)."""
    enviar(host, VACIO)
    return host


def reporte_telnet(bind="0.0.0.0"):
    return {
        "processes": [{"pid": 50, "name": "telnetd", "username": "root"}],
        "ports": [{"port": 23, "protocol": "tcp", "bind_address": bind, "pid": 50}],
    }


def test_telnet_publico_genera_alerta_critica(client, registrar, crear_host, enviar):
    headers = registrar()
    r = enviar(con_primer_reporte(enviar, crear_host(headers)), reporte_telnet())
    assert r.json()["score"] == 70
    alertas = client.get("/alerts", headers=headers).json()
    assert len(alertas) == 1
    assert alertas[0]["severity"] == "critica"
    assert alertas[0]["confidence"] == "alta"


def test_telnet_solo_local_no_genera_alerta(client, registrar, crear_host, enviar):
    headers = registrar()
    r = enviar(con_primer_reporte(enviar, crear_host(headers)), reporte_telnet("127.0.0.1"))
    assert r.json()["score"] == 100
    assert client.get("/alerts", headers=headers).json() == []


def test_mismo_reporte_no_duplica_alertas(client, registrar, crear_host, enviar):
    headers = registrar()
    host = con_primer_reporte(enviar, crear_host(headers))
    enviar(host, reporte_telnet())
    enviar(host, reporte_telnet())
    assert len(client.get("/alerts", headers=headers).json()) == 1


def test_cambiar_estado_de_alerta(client, registrar, crear_host, enviar):
    headers = registrar()
    enviar(con_primer_reporte(enviar, crear_host(headers)), reporte_telnet())
    alerta = client.get("/alerts", headers=headers).json()[0]
    r = client.patch(
        f"/alerts/{alerta['id']}", json={"status": "atendida"}, headers=headers
    )
    assert r.status_code == 200
    assert r.json()["status"] == "atendida"
    assert client.get("/alerts?status=nueva", headers=headers).json() == []


def test_alerta_ajena_da_404(client, registrar, crear_host, enviar):
    a = registrar("a@correo.com")
    b = registrar("b@correo.com")
    enviar(con_primer_reporte(enviar, crear_host(a)), reporte_telnet())
    alerta = client.get("/alerts", headers=a).json()[0]
    r = client.patch(f"/alerts/{alerta['id']}", json={"status": "atendida"}, headers=b)
    assert r.status_code == 404


def test_ejecutable_en_tmp_con_puerto_publico(client, registrar, crear_host, enviar):
    headers = registrar()
    reporte = {
        "processes": [
            {"pid": 70, "name": "tmpbin", "exe_path": "/tmp/tmpbin", "exe_deleted": True}
        ],
        "ports": [{"port": 4444, "protocol": "tcp", "bind_address": "0.0.0.0", "pid": 70}],
    }
    r = enviar(con_primer_reporte(enviar, crear_host(headers)), reporte)
    assert r.json()["score"] == 77
    assert len(client.get("/alerts", headers=headers).json()) == 2


# ---- primer reporte y cambios
def test_primer_reporte_no_genera_alertas_aunque_tenga_hallazgos(client, registrar, crear_host, enviar):
    headers = registrar()
    r = enviar(crear_host(headers), reporte_telnet())
    assert r.json()["score"] == 70  # el puntaje sí cuenta
    assert client.get("/alerts", headers=headers).json() == []


def test_hallazgo_que_ya_estaba_no_genera_alerta_despues(client, registrar, crear_host, enviar):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, reporte_telnet())
    enviar(host, reporte_telnet())
    assert client.get("/alerts", headers=headers).json() == []


def test_hallazgo_marcado_como_normal_no_alerta(client, registrar, crear_host, enviar):
    headers = registrar()
    host = con_primer_reporte(enviar, crear_host(headers))
    r = client.put(
        "/review/normal",
        json={"port": 23, "protocol": "tcp", "exe_path": None, "normal": True},
        headers=headers,
    )
    assert r.status_code == 204
    enviar(host, reporte_telnet())
    assert client.get("/alerts", headers=headers).json() == []
