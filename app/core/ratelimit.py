"""Límites de peticiones en memoria (ventana deslizante).

Protege contra fuerza bruta (login, 2FA), abuso de endpoints costosos y ráfagas de un mismo cliente.
IMPORTANTE: los contadores viven en la memoria de cada proceso. Con varios workers/instancias cada una
cuenta por separado y la protección real ante un DDoS volumétrico debe estar en el borde (Cloudflare,
WAF/proxy del proveedor). Para compartir contadores entre instancias, sustituye `SlidingWindow` por Redis.
"""
import math
import threading
import time
from collections import deque

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse

from app.core import config

# nombre: (peticiones, ventana en segundos)
LIMITES: dict[str, tuple[int, int]] = {
    "global": (300, 60),         # por IP, todas las rutas
    "login": (10, 60),           # por IP
    "login-fallos-ip": (5, 900),     # fallos por (correo + IP)
    "login-fallos-cuenta": (20, 900),  # fallos por correo, desde cualquier IP
    "totp": (10, 60),            # por IP
    "totp-fallos": (5, 300),     # códigos erróneos por usuario
    "register": (10, 3600),      # por IP
    "enroll": (10, 60),          # por IP (vinculación del agente)
    "enroll-token": (10, 60),    # por IP
    "installer": (20, 60),       # por IP
    "reports": (120, 60),        # por equipo (llave de API)
    "telegram-test": (3, 60),    # por IP: evita spamear tu chat
    "telegram": (20, 60),        # por IP
}


class SlidingWindow:
    def __init__(self, max_keys: int = 100_000) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self.max_keys = max_keys

    def _evict(self, now: float) -> None:  # con el lock tomado
        for k in [k for k, dq in self._hits.items() if not dq or dq[-1] < now - 3600]:
            del self._hits[k]
        if len(self._hits) >= self.max_keys:  # aun así lleno: descarta el 10 % más antiguo
            for k in sorted(self._hits, key=lambda k: self._hits[k][-1])[: self.max_keys // 10]:
                del self._hits[k]

    def hit(self, key: str, limit: int, window: int) -> int:
        """Registra un intento. Devuelve 0 si se permite o los segundos de espera si se excede."""
        now = time.monotonic()
        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                if len(self._hits) >= self.max_keys:
                    self._evict(now)
                dq = self._hits[key] = deque()
            while dq and dq[0] <= now - window:
                dq.popleft()
            if len(dq) >= limit:
                return max(1, math.ceil(dq[0] + window - now))
            dq.append(now)
            return 0

    def blocked(self, key: str, limit: int, window: int) -> int:
        """Segundos de espera si `key` ya acumuló `limit` fallos en la ventana (sin registrar nada)."""
        now = time.monotonic()
        with self._lock:
            dq = self._hits.get(key)
            if not dq:
                return 0
            while dq and dq[0] <= now - window:
                dq.popleft()
            return max(1, math.ceil(dq[0] + window - now)) if len(dq) >= limit else 0

    def fail(self, key: str) -> None:
        with self._lock:
            self._hits.setdefault(key, deque()).append(time.monotonic())

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindow()


def too_many(retry: int) -> HTTPException:
    return HTTPException(
        429, f"Demasiados intentos. Espera {retry} s e inténtalo de nuevo.", headers={"Retry-After": str(retry)}
    )


def client_ip(headers, client_host: str | None) -> str:
    """IP del cliente. Solo se confía en cabeceras de proxy si lo configuraste (si no, se podrían falsear)."""
    if config.CLIENT_IP_HEADER:
        v = headers.get(config.CLIENT_IP_HEADER.lower())
        if v:
            return v.split(",")[0].strip()
    hops = config.TRUSTED_PROXY_HOPS
    if hops > 0:
        partes = [p.strip() for p in (headers.get("x-forwarded-for") or "").split(",") if p.strip()]
        if len(partes) >= hops:
            return partes[-hops]  # la IP que añadió el proxy más cercano a nosotros; las de la izquierda las controla el cliente
    return client_host or "desconocido"


def rate_limit(name: str):
    """Dependencia de FastAPI: limita por IP según LIMITES[name]."""

    def dep(request: Request) -> None:
        if not config.RATE_LIMIT_ENABLED:
            return
        limit, window = LIMITES[name]
        ip = client_ip(request.headers, request.client.host if request.client else None)
        retry = limiter.hit(f"{name}:{ip}", limit, window)
        if retry:
            raise too_many(retry)

    return dep


def hit_key(name: str, ident: str | int) -> None:
    """Límite por identificador (p. ej. el equipo que reporta)."""
    if not config.RATE_LIMIT_ENABLED:
        return
    limit, window = LIMITES[name]
    retry = limiter.hit(f"{name}:{ident}", limit, window)
    if retry:
        raise too_many(retry)


class LimiteGlobal:
    """Middleware ASGI: tope de peticiones por IP en todas las rutas."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not config.RATE_LIMIT_ENABLED or scope["method"] == "OPTIONS":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        ip = client_ip(headers, (scope.get("client") or (None,))[0])
        limit, window = LIMITES["global"]
        retry = limiter.hit(f"global:{ip}", limit, window)
        if retry:
            r = JSONResponse(
                {"detail": f"Demasiadas peticiones. Espera {retry} s."}, status_code=429, headers={"Retry-After": str(retry)}
            )
            await r(scope, receive, send)
            return
        await self.app(scope, receive, send)
