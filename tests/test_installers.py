def _token(client, headers):
    return client.post("/hosts/enroll-token", headers=headers).json()["enroll_token"]


def test_instalador_linux_lleva_token_y_se_descarga(client, registrar):
    token = _token(client, registrar())
    r = client.get(f"/installers/instalar-{token}.sh")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert token in r.text
    assert "https://api.example" in r.text
    assert "https://releases.example/portalert-agent-linux" in r.text
    assert r.headers["cache-control"] == "no-store"


def test_instalador_windows(client, registrar):
    token = _token(client, registrar())
    r = client.get(f"/installers/instalar-{token}.ps1")
    assert r.status_code == 200 and token in r.text and "Register-ScheduledTask" in r.text


def test_instalador_con_token_invalido(client):
    assert client.get("/installers/instalar-" + "x" * 40 + ".sh").status_code == 404


def test_instalador_ya_no_sirve_tras_vincular(client, registrar):
    token = _token(client, registrar())
    body = {"enroll_token": token, "name": "pc", "os_family": "linux"}
    assert client.get(f"/installers/instalar-{token}.sh").status_code == 200
    assert client.post("/hosts/enroll", json=body).status_code == 201
    assert client.get(f"/installers/instalar-{token}.sh").status_code == 404


def test_descargar_el_instalador_no_consume_el_token(client, registrar):
    token = _token(client, registrar())
    client.get(f"/installers/instalar-{token}.sh")
    client.get(f"/installers/instalar-{token}.sh")
    body = {"enroll_token": token, "name": "pc", "os_family": "linux"}
    assert client.post("/hosts/enroll", json=body).status_code == 201


def test_host_recien_vinculado_no_tiene_score_hasta_su_primer_reporte(registrar, crear_host):
    # el front usa score == null para distinguir "vinculado" de "primer reporte recibido"
    assert crear_host(registrar())["score"] is None


def test_instalador_windows_se_eleva_solo(client, registrar):
    token = _token(client, registrar())
    texto = client.get(f"/installers/instalar-{token}.ps1").text
    assert "param([switch]$Elevado)" in texto
    assert "-Verb RunAs" in texto and "$PSCommandPath" in texto
    assert texto.index("-Verb RunAs") < texto.index("Invoke-WebRequest")
