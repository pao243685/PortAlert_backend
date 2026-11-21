import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SECRET_KEY = os.environ["SECRET_KEY"]
if len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY es demasiado corta (mínimo 32 caracteres). Genera una con: "
        'python -c "import secrets; print(secrets.token_urlsafe(48))"'
    )
# Llave Fernet con la que la APLICACION cifra totp_secret antes de guardarlo.
# Generar con:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
TOTP_ENCRYPTION_KEY = os.environ["TOTP_ENCRYPTION_KEY"]
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
MFA_TOKEN_MINUTES = int(os.getenv("MFA_TOKEN_MINUTES", "5"))
ENROLL_TOKEN_MINUTES = int(os.getenv("ENROLL_TOKEN_MINUTES", "10"))
# URL publica de ESTA api (la que el agente usara para vincularse y reportar).
# Si se omite se deduce de la peticion, que detras de un proxy suele salir con http://.
PUBLIC_API_URL = os.getenv("PUBLIC_API_URL", "").rstrip("/")
# Donde se publican los binarios del agente (p. ej. GitHub Releases) y su sha256 (opcional pero recomendado).
AGENT_DOWNLOAD_URL_LINUX = os.getenv("AGENT_DOWNLOAD_URL_LINUX", "")
AGENT_DOWNLOAD_URL_WINDOWS = os.getenv("AGENT_DOWNLOAD_URL_WINDOWS", "")
AGENT_SHA256_LINUX = os.getenv("AGENT_SHA256_LINUX", "").lower()
AGENT_SHA256_WINDOWS = os.getenv("AGENT_SHA256_WINDOWS", "").lower()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "").lstrip("@")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
TELEGRAM_LINK_MINUTES = int(os.getenv("TELEGRAM_LINK_MINUTES", "10"))

# --- seguridad ---
APP_ENV = os.getenv("APP_ENV", "development")  # "production": sin /docs, con HSTS y CSP estricta
IS_PROD = APP_ENV == "production"
ALLOWED_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()]  # p. ej. api.tudominio.com
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "1") != "0"
# Detrás de un proxy/CDN todas las peticiones llegan con la IP del proxy: indica cómo leer la IP real.
CLIENT_IP_HEADER = os.getenv("CLIENT_IP_HEADER", "")  # p. ej. CF-Connecting-IP (Cloudflare) o Fly-Client-IP (Fly.io)
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "0"))  # proxies de confianza delante (usa X-Forwarded-For)
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "100000"))  # tope para el resto de peticiones (/reports tiene el suyo)
