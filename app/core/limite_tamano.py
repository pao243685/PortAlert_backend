from starlette.responses import JSONResponse


class LimiteReportes:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or scope["path"] != "/reports"
        ):
            await self.app(scope, receive, send)
            return

        total = 0
        partes = []
        while True:
            mensaje = await receive()
            if mensaje["type"] != "http.request":
                break
            cuerpo = mensaje.get("body", b"")
            total += len(cuerpo)
            if total > self.max_bytes:
                respuesta = JSONResponse(
                    {"detail": "Reporte demasiado grande"}, status_code=413
                )
                await respuesta(scope, receive, send)
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
