import os

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SECRET_KEY = os.environ["SECRET_KEY"]
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
ENROLL_TOKEN_MINUTES = int(os.getenv("ENROLL_TOKEN_MINUTES", "10"))
PUBLIC_API_URL = os.getenv("PUBLIC_API_URL", "").rstrip("/")

AGENT_DOWNLOAD_URL_LINUX = os.getenv("AGENT_DOWNLOAD_URL_LINUX", "")
AGENT_DOWNLOAD_URL_WINDOWS = os.getenv("AGENT_DOWNLOAD_URL_WINDOWS", "")
AGENT_SHA256_LINUX = os.getenv("AGENT_SHA256_LINUX", "").lower()
AGENT_SHA256_WINDOWS = os.getenv("AGENT_SHA256_WINDOWS", "").lower()