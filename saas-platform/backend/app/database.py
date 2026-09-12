from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import DATABASE_URL

if DATABASE_URL.startswith("sqlite"):
    # Scans finish on a background thread, so the connection must be usable
    # off the thread that opened it.
    _db_file = DATABASE_URL.split("///", 1)[-1]
    if _db_file and _db_file != ":memory:":
        Path(_db_file).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
