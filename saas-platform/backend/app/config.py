"""
Central settings, loaded from environment variables (.env in this directory).

AEGIS_REPO_PATH must point at the Aegis Scanner checkout so aegis_bridge.py can
import its modules as a library (never as a subprocess — see integration rules
in the project brief).
"""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

AEGIS_REPO_PATH = os.environ.get(
    "AEGIS_REPO_PATH", str(Path(__file__).resolve().parent.parent.parent.parent)
)

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg2://aegis_saas:aegis_saas@localhost:5432/aegis_saas"
)

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "1440"))

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Root the web platform writes/reads Aegis reports under (Aegis's own output/ dir).
AEGIS_OUTPUT_DIR = os.path.join(AEGIS_REPO_PATH, "output")

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")
