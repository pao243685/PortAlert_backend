import os

os.environ["DATABASE_URL"] = "sqlite:///./test_portalert.db"

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