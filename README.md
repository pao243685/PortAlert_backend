# PortAlert - Backend

API en FastAPI para PortAlert. Se conecta a una base PostgreSQL que vive en otro repositorio.

## Levantar en local
```bash
cp .env.example .env      
uv venv && uv pip install -r requirements.txt
uv run uvicorn app.main:app --reload --port 8001
```
Comprueba en http://localhost:8001/health que responda `{"status":"ok","db":"ok"}`.
Documentación interactiva: http://localhost:8001/docs


## Telegram
1. Crea un bot con @BotFather y copia el token.
2. En `.env` pon `TELEGRAM_BOT_TOKEN` y `TELEGRAM_BOT_USERNAME` (sin la @).
3. Sin `TELEGRAM_WEBHOOK_SECRET` la API recibe los mensajes del bot por polling, sin necesitar URL pública. Para producción define el secreto y registra el webhook apuntando a `POST /telegram/webhook`:
```bash
curl -s "https://api.telegram.org/bot<TOKEN>/setWebhook" \
  -d "url=https://TU-API/telegram/webhook" -d "secret_token=<TELEGRAM_WEBHOOK_SECRET>"
```
Con el token vacío las notificaciones quedan desactivadas y el frontend lo indica.
