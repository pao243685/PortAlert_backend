from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core import config
from app.core.config import FRONTEND_URL
from app.core.constants import MAX_BYTES_REPORTE
from app.core.limite_tamano import LimiteReportes
from app.core.ratelimit import LimiteGlobal
from app.core.security_headers import CabecerasSeguras
from app.routers import (
    alerts, auth, health, hosts, installers, panel, ports, reports, review, telegram,
)
from app.services.telegram import iniciar_polling, iniciar_vigilancia


@asynccontextmanager
async def lifespan(_: FastAPI):
    paradas = [iniciar_polling(), iniciar_vigilancia()]
    yield
    for parar in paradas:
        if parar:
            parar.set()


# En producción no se publica la documentación interactiva ni el esquema de la API.
app = FastAPI(
    title="PortAlert API",
    lifespan=lifespan,
    docs_url=None if config.IS_PROD else "/docs",
    redoc_url=None if config.IS_PROD else "/redoc",
    openapi_url=None if config.IS_PROD else "/openapi.json",
)

# add_middleware: el último que se agrega queda más afuera. Orden de afuera hacia adentro:
# hosts permitidos -> cabeceras seguras -> CORS -> tope global por IP -> tope de tamaño -> rutas.
# (El tope por IP va dentro de CORS para que sus respuestas 429 también lleven cabeceras CORS.)
app.add_middleware(LimiteReportes, max_bytes=MAX_BYTES_REPORTE, max_general=config.MAX_BODY_BYTES)
app.add_middleware(LimiteGlobal)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["Retry-After"],
    max_age=600,
)
app.add_middleware(CabecerasSeguras)
if config.ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.ALLOWED_HOSTS)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(hosts.router)
app.include_router(installers.router)
app.include_router(review.router)
app.include_router(panel.router)
app.include_router(ports.router)
app.include_router(reports.router)
app.include_router(alerts.router)
app.include_router(telegram.router)
