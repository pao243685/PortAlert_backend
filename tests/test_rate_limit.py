import pytest

from app.core import config, ratelimit
from tests.test_analyzer import VACIO

PW = "Zorro-Azul-47!"


@pytest.fixture
def limites(monkeypatch):
    """Permite bajar un límite para probarlo sin disparar decenas de peticiones."""

    def poner(nombre, limite, ventana=60):
        monkeypatch.setitem(ratelimit.LIMITES, nombre, (limite, ventana))

    return poner


def _login(client, email, password, **kw):
    return client.post("/auth/login", data={"username": email, "password": password}, **kw)


def test_login_tiene_tope_por_ip(client, registrar, limites):
    registrar()  # el registrar() de pruebas ya hizo 1 login
    limites("login", 4)
    codigos = [_login(client, "a@correo.com", PW).status_code for _ in range(5)]
    assert codigos == [200, 200, 200, 429, 429]
    r = _login(client, "a@correo.com", PW)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


def test_la_cuenta_se_bloquea_tras_5_contrasenas_erroneas(client, registrar):
    registrar()
    for _ in range(5):
        assert _login(client, "a@correo.com", "equivocada-1A!").status_code == 401
    r = _login(client, "a@correo.com", PW)  # ni la correcta pasa mientras dura el bloqueo
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_un_login_correcto_reinicia_el_contador_de_la_ip(client, registrar):
    registrar()
    for _ in range(4):
        _login(client, "a@correo.com", "equivocada-1A!")
    assert _login(client, "a@correo.com", PW).status_code == 200
    for _ in range(4):
        assert _login(client, "a@correo.com", "equivocada-1A!").status_code == 401  # empieza de cero


def test_el_bloqueo_es_por_ip_no_tumba_la_cuenta_a_otro_cliente(client, registrar, monkeypatch):
    registrar()
    monkeypatch.setattr(config, "CLIENT_IP_HEADER", "x-real-ip")
    for _ in range(5):
        _login(client, "a@correo.com", "equivocada-1A!", headers={"x-real-ip": "1.1.1.1"})
    assert _login(client, "a@correo.com", PW, headers={"x-real-ip": "1.1.1.1"}).status_code == 429
    assert _login(client, "a@correo.com", PW, headers={"x-real-ip": "2.2.2.2"}).status_code == 200


def test_correo_inexistente_tambien_cuenta_y_responde_igual(client):
    for _ in range(5):
        r = _login(client, "no-existe@correo.com", "equivocada-1A!")
        assert r.status_code == 401 and r.json()["detail"] == "Credenciales incorrectas"
    assert _login(client, "no-existe@correo.com", "equivocada-1A!").status_code == 429


def test_codigo_2fa_no_se_puede_adivinar_a_fuerza_bruta(client, registrar):
    import pyotp, time

    headers = registrar()
    secreto = client.post("/auth/totp/setup", headers=headers).json()["secret"]
    client.post("/auth/totp/enable", json={"code": pyotp.TOTP(secreto).at(time.time())}, headers=headers)
    mfa = _login(client, "a@correo.com", PW).json()["mfa_token"]
    codigos = [client.post("/auth/login/totp", json={"mfa_token": mfa, "code": f"{i:06d}"}).status_code for i in range(7)]
    assert codigos[:5] == [401] * 5 and codigos[5:] == [429, 429]
    # y el código correcto tampoco entra mientras dura el bloqueo
    bueno = pyotp.TOTP(secreto).at(time.time() + 30)
    assert client.post("/auth/login/totp", json={"mfa_token": mfa, "code": bueno}).status_code == 429


def test_registro_tiene_tope_por_ip(client, limites):
    limites("register", 2, 3600)
    codigos = [client.post("/auth/register", json={"email": f"u{i}@correo.com", "password": PW}).status_code for i in range(4)]
    assert codigos == [201, 201, 429, 429]


def test_reportes_tienen_tope_por_equipo(client, registrar, crear_host, limites):
    host = crear_host(registrar())
    limites("reports", 3)
    h = {"X-API-Key": host["api_key"]}
    assert [client.post("/reports", json=VACIO, headers=h).status_code for _ in range(5)] == [201, 201, 201, 429, 429]


def test_tope_global_por_ip_incluye_cabeceras_cors(client, limites):
    limites("global", 5)
    origen = {"Origin": config.FRONTEND_URL}
    codigos = [client.get("/health", headers=origen).status_code for _ in range(7)]
    assert codigos[:5] == [200] * 5 and codigos[5:] == [429, 429]
    r = client.get("/health", headers=origen)
    assert r.headers["access-control-allow-origin"] == config.FRONTEND_URL and "retry-after" in r.headers
    assert "retry-after" in r.headers["access-control-expose-headers"].lower()


def test_instalador_y_enroll_tienen_tope(client, limites):
    limites("enroll", 2)
    cuerpo = {"enroll_token": "x" * 40, "name": "pc", "os_family": "linux"}
    assert [client.post("/hosts/enroll", json=cuerpo).status_code for _ in range(4)] == [401, 401, 429, 429]
    limites("installer", 2)
    assert [client.get("/installers/instalar-" + "x" * 40 + ".sh").status_code for _ in range(4)] == [404, 404, 429, 429]


def test_x_forwarded_for_se_ignora_si_no_hay_proxy_de_confianza(client, registrar, limites):
    registrar()  # ya hizo 1 login desde la misma IP
    limites("login", 3)
    codigos = [_login(client, "a@correo.com", PW, headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code for i in range(4)]
    assert codigos == [200, 200, 429, 429]  # falsear la cabecera no sirve para esquivar el límite


def test_con_un_proxy_de_confianza_se_usa_la_ip_que_el_proxy_anade(client, registrar, limites, monkeypatch):
    registrar()
    monkeypatch.setattr(config, "TRUSTED_PROXY_HOPS", 1)
    limites("login", 2)
    h = lambda real: {"X-Forwarded-For": f"6.6.6.6, {real}"}  # lo de la izquierda lo escribe el cliente; lo de la derecha, el proxy
    assert [_login(client, "a@correo.com", PW, headers=h("3.3.3.3")).status_code for _ in range(3)] == [200, 200, 429]
    assert _login(client, "a@correo.com", PW, headers=h("4.4.4.4")).status_code == 200


def test_el_limitador_no_crece_sin_control():
    w = ratelimit.SlidingWindow(max_keys=50)
    for i in range(500):
        w.hit(f"k{i}", 5, 60)
    assert len(w._hits) <= 50
