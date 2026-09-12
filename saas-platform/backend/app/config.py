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

BACKEND_DIR = Path(__file__).resolve().parent.parent

# SQLite by default so a fresh clone runs with zero database setup (the
# launcher relies on this). Point DATABASE_URL at Postgres for production.
DATABASE_URL = os.environ.get(
    "DATABASE_URL", f"sqlite:///{(BACKEND_DIR / 'data' / 'aegis_shield.db').as_posix()}"
)

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "1440"))

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Root the web platform writes/reads Aegis reports under (Aegis's own output/ dir).
AEGIS_OUTPUT_DIR = os.path.join(AEGIS_REPO_PATH, "output")

CORS_ORIGINS = [
    o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()
]
# The hosted GitHub Pages frontend is always allowed, so it can talk to a
# backend someone is running on their own machine (http://localhost:8000).
PUBLIC_FRONTEND_ORIGIN = os.environ.get("PUBLIC_FRONTEND_ORIGIN", "https://syedj-hacks.github.io")
if PUBLIC_FRONTEND_ORIGIN and PUBLIC_FRONTEND_ORIGIN not in CORS_ORIGINS:
    CORS_ORIGINS.append(PUBLIC_FRONTEND_ORIGIN)

# Built React app. When present, the backend serves it at / so the whole
# product runs from one port (this is what the one-click launcher uses).
FRONTEND_DIST = os.environ.get(
    "FRONTEND_DIST", str(BACKEND_DIR.parent / "frontend" / "dist")
)
