from app.core import config


def test_cabeceras_de_seguridad(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    assert "permissions-policy" in r.headers


def test_tokens_no_se_guardan_en_cache(client, registrar):
    registrar()
    r = client.post("/auth/login", data={"username": "a@correo.com", "password": "Zorro-Azul-47!"})
    assert r.headers["cache-control"] == "no-store"


def test_cors_solo_permite_el_origen_del_frontend(client):
    pre = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,authorization"}
    ok = client.options("/auth/login", headers={"Origin": config.FRONTEND_URL, **pre})
    assert ok.headers["access-control-allow-origin"] == config.FRONTEND_URL
    ajeno = client.options("/auth/login", headers={"Origin": "https://sitio-malicioso.example", **pre})
    assert "access-control-allow-origin" not in ajeno.headers
    raro = client.options("/auth/login", headers={"Origin": config.FRONTEND_URL, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-evil"})
    assert raro.status_code == 400


def test_cuerpos_gigantes_se_rechazan_con_413(client):
    r = client.post("/auth/login", content=b"a=" + b"x" * 300_000, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    r = client.post("/auth/register", json={"email": "a@correo.com", "password": "Zorro-Azul-47!" * 20_000})
    assert r.status_code == 413


def test_los_reportes_conservan_su_propio_tope(client, registrar, crear_host):
    from app.core.constants import MAX_BYTES_REPORTE

    host = crear_host(registrar())
    r = client.post("/reports", content=b"x" * (MAX_BYTES_REPORTE + 10), headers={"X-API-Key": host["api_key"], "Content-Type": "application/json"})
    assert r.status_code == 413 and "Reporte" in r.json()["detail"]


def test_secret_key_corta_impide_arrancar():
    import subprocess, sys, os

    env = {**os.environ, "SECRET_KEY": "corta", "DATABASE_URL": "sqlite:///./x.db", "TOTP_ENCRYPTION_KEY": os.environ["TOTP_ENCRYPTION_KEY"]}
    r = subprocess.run([sys.executable, "-c", "import app.core.config"], env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "SECRET_KEY" in r.stderr
