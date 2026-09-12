"""Engine / session setup. Defaults to a local SQLite file; set DATABASE_URL for Postgres etc."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from vulngent.config import get_settings
from vulngent.db.models import Base

_settings = get_settings()

_connect_args = {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}
engine = create_engine(_settings.database_url, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def ensure_schema() -> None:
    """Idempotent column adds for databases created before a column existed.

    create_all only creates missing tables, never alters them; keep lightweight
    ADD COLUMN migrations here so an existing SQLite file keeps working.
    Currently only applied on SQLite (local dev default)."""
    if engine.url.get_backend_name() != "sqlite":
        return
    with engine.begin() as conn:
        rows = conn.exec_driver_sql("PRAGMA table_info(chat_threads)").all()
        if rows and "archived_at" not in {r[1] for r in rows}:
            conn.exec_driver_sql("ALTER TABLE chat_threads ADD COLUMN archived_at DATETIME")


@contextmanager
def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
