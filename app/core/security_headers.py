from app.core import config


class CabecerasSeguras:
    """Middleware ASGI: cabeceras de seguridad en todas las respuestas de la API."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def enviar(message):
            if message["type"] == "http.response.start":
                h = dict((k.lower(), v) for k, v in message.get("headers", []))
                extra = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                    b"cross-origin-resource-policy": b"same-site",
                }
                if b"cache-control" not in h:
                    extra[b"cache-control"] = b"no-store"  # nada de la API (tokens, datos) debe quedar en cachés
                if config.IS_PROD:
                    extra[b"content-security-policy"] = b"default-src 'none'; frame-ancestors 'none'"
                    extra[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                message["headers"] = [*message.get("headers", []), *((k, v) for k, v in extra.items() if k not in h)]
            await send(message)

        await self.app(scope, receive, enviar)
