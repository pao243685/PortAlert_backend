from starlette.responses import JSONResponse


class LimiteReportes:
    """Rechaza cuerpos demasiado grandes. /reports tiene su propio tope; el resto de POST/PUT/PATCH, `max_general`."""

    def __init__(self, app, max_bytes: int, max_general: int = 100_000):
        self.app = app
        self.max_bytes = max_bytes
        self.max_general = max_general

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        limite = self.max_bytes if scope["path"] == "/reports" else self.max_general
        detalle = "Reporte demasiado grande" if scope["path"] == "/reports" else "Petición demasiado grande"

        declarado = dict(scope["headers"]).get(b"content-length")
        if declarado and declarado.isdigit() and int(declarado) > limite:
            await JSONResponse({"detail": detalle}, status_code=413)(scope, receive, send)
            return

        total = 0
        partes = []
        while True:
            mensaje = await receive()
            if mensaje["type"] != "http.request":
                break
            cuerpo = mensaje.get("body", b"")
            total += len(cuerpo)
            if total > limite:
                await JSONResponse({"detail": detalle}, status_code=413)(scope, receive, send)
                return
            partes.append(cuerpo)
            if not mensaje.get("more_body", False):
                break

        completo = b"".join(partes)
        entregado = False

        async def reenviar():
            nonlocal entregado
            if not entregado:
                entregado = True
                return {"type": "http.request", "body": completo, "more_body": False}
            return await receive()

        await self.app(scope, reenviar, send)
