import os

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SECRET_KEY = os.environ["SECRET_KEY"]
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
