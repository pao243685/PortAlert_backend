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