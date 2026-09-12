from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func

from . import aegis_bridge, models  # noqa: F401  (import order: chdir/sys.path happens here)
from .config import CORS_ORIGINS
from .database import Base, SessionLocal, engine
from .routers import admin, auth, billing, scans

app = FastAPI(title="Aegis Shield", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(billing.router)
app.include_router(scans.router)
app.include_router(admin.router)


@app.on_event("startup")
def on_startup():
    # App tables (idempotent — Alembic owns real migrations, this is a safety
    # net for `python -m app.main` without running migrations first).
    Base.metadata.create_all(bind=engine)

    # Aegis's own SQLite schema (idempotent per BACKEND_STRUCTURE.md).
    aegis_bridge.aegis_init_db()

    # Hard startup guard: at most one admin account may ever exist, and it
    # must be the one seed_admin.py created from ADMIN_EMAIL/ADMIN_PASSWORD.
    # Public registration can never produce an admin (see routers/auth.py),
    # so more than one here means the DB was tampered with directly.
    db = SessionLocal()
    try:
        admin_count = db.query(func.count(models.User.id)).filter(
            models.User.role == models.Role.admin
        ).scalar()
        if admin_count > 1:
            raise RuntimeError(
                f"Refusing to start: {admin_count} admin accounts found, expected at most 1. "
                "Investigate before booting the app."
            )
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}
