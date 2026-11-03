import os

from cryptography.fernet import Fernet

os.environ["DATABASE_URL"] = "sqlite:///./test_portalert.db"
os.environ["SECRET_KEY"] = "clave-de-pruebas"
os.environ["TOTP_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["AGENT_DOWNLOAD_URL_LINUX"] = "https://releases.example/portalert-agent-linux"
os.environ["AGENT_DOWNLOAD_URL_WINDOWS"] = "https://releases.example/portalert-agent.exe"
os.environ["PUBLIC_API_URL"] = "https://api.example"

import pytest
from fastapi.testclient import TestClient

from app import models  # noqa: F401  (registra las tablas en Base)
from app.core.database import Base, engine
from app.main import app


@pytest.fixture(autouse=True)
def base_limpia():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture(scope="session", autouse=True)
def borrar_db_al_final():
    yield
    engine.dispose()
    if os.path.exists("test_portalert.db"):
        os.remove("test_portalert.db")


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def registrar(client):
    def _registrar(email="a@correo.com", password="Clave12345"):
        client.post("/auth/register", json={"email": email, "password": password})
        r = client.post("/auth/login", data={"username": email, "password": password})
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    return _registrar


@pytest.fixture
def crear_host(client):
    """Vincula un dispositivo con el flujo real: token -> enroll del agente."""

    def _crear(headers, nombre="laptop"):
        t = client.post("/hosts/enroll-token", headers=headers).json()["enroll_token"]
        r = client.post(
            "/hosts/enroll",
            json={
                "enroll_token": t,
                "name": nombre,
                "os_family": "linux",
                "os_version": "Ubuntu 22.04",
            },
        )
        return r.json()

    return _crear


@pytest.fixture
def enviar(client):
    def _enviar(host, reporte):
        return client.post(
            "/reports", json=reporte, headers={"X-API-Key": host["api_key"]}
        )

    return _enviar
