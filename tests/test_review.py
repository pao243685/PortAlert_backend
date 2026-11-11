TELNET_Y_SSH = {
    "processes": [
        {"pid": 50, "name": "telnetd", "exe_path": "/usr/sbin/in.telnetd", "username": "root", "package": "telnetd"},
        {"pid": 51, "name": "sshd", "exe_path": "/usr/sbin/sshd", "username": "root", "package": "openssh-server"},
    ],
    "ports": [
        {"port": 23, "protocol": "tcp", "bind_address": "0.0.0.0", "pid": 50},
        {"port": 22, "protocol": "tcp", "bind_address": "0.0.0.0", "pid": 51},
    ],
}


def test_revision_sin_equipo_o_sin_reporte(client, registrar, crear_host):
    headers = registrar()
    assert client.get("/review", headers=headers).status_code == 404
    crear_host(headers)
    assert client.get("/review", headers=headers).status_code == 404


def test_revision_lista_hallazgos_del_primer_reporte(client, registrar, crear_host, enviar):
    headers = registrar()
    enviar(crear_host(headers), TELNET_Y_SSH)
    r = client.get("/review", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["counts"] == {"critica": 1, "alta": 0, "media": 0, "baja": 1}
    assert data["review_completed"] is False
    assert [f["severity"] for f in data["findings"]] == ["critica", "baja"]  # de mayor a menor
    telnet = data["findings"][0]
    assert telnet["port"] == 23 and telnet["protocol"] == "tcp"
    assert telnet["process"] == "telnetd" and telnet["exe_path"] == "/usr/sbin/in.telnetd"
    assert telnet["username"] == "root" and telnet["package"] == "telnetd"
    assert telnet["bind_address"] == "0.0.0.0" and telnet["can_mark_normal"] is True


def test_la_revision_usa_siempre_el_primer_reporte(client, registrar, crear_host, enviar):
    headers = registrar()
    host = crear_host(headers)
    enviar(host, TELNET_Y_SSH)
    enviar(host, {"processes": [], "ports": []})
    assert client.get("/review", headers=headers).json()["counts"]["critica"] == 1


def test_marcar_y_desmarcar_normal(client, registrar, crear_host, enviar):
    headers = registrar()
    enviar(crear_host(headers), TELNET_Y_SSH)
    cuerpo = {"port": 22, "protocol": "tcp", "exe_path": "/usr/sbin/sshd"}
    assert client.put("/review/normal", json={**cuerpo, "normal": True}, headers=headers).status_code == 204
    # idempotente
    assert client.put("/review/normal", json={**cuerpo, "normal": True}, headers=headers).status_code == 204
    ssh = [f for f in client.get("/review", headers=headers).json()["findings"] if f["port"] == 22][0]
    assert ssh["is_normal"] is True
    client.put("/review/normal", json={**cuerpo, "normal": False}, headers=headers)
    ssh = [f for f in client.get("/review", headers=headers).json()["findings"] if f["port"] == 22][0]
    assert ssh["is_normal"] is False


def test_terminar_revision(client, registrar, crear_host, enviar):
    headers = registrar()
    enviar(crear_host(headers), TELNET_Y_SSH)
    r = client.post("/review/complete", headers=headers)
    assert r.status_code == 200 and r.json()["review_completed_at"] is not None
    assert client.get("/review", headers=headers).json()["review_completed"] is True
    assert client.get("/hosts", headers=headers).json()[0]["review_completed_at"] is not None


def test_la_revision_es_privada(client, registrar, crear_host, enviar):
    a, b = registrar("a@correo.com"), registrar("b@correo.com")
    enviar(crear_host(a), TELNET_Y_SSH)
    assert client.get("/review", headers=b).status_code == 404
