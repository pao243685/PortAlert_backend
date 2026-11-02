from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import FRONTEND_URL
from app.core.constants import MAX_BYTES_REPORTE
from app.core.limite_tamano import LimiteReportes
from app.routers import auth, health, hosts, installers, reports

app = FastAPI(title="PortAlert API")

app.add_middleware(LimiteReportes, max_bytes=MAX_BYTES_REPORTE)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(hosts.router)
app.include_router(installers.router)
app.include_router(reports.router)
