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
    # New tables (e.g. users) are safe to create everywhere; create_all only adds
    # what's missing and never touches existing tables.
    Base.metadata.create_all(engine)
    if engine.url.get_backend_name() != "sqlite":
        return
    with engine.begin() as conn:
        rows = conn.exec_driver_sql("PRAGMA table_info(chat_threads)").all()
        cols = {r[1] for r in rows}
        if rows and "archived_at" not in cols:
            conn.exec_driver_sql("ALTER TABLE chat_threads ADD COLUMN archived_at DATETIME")
        if rows and "owner_id" not in cols:
            conn.exec_driver_sql("ALTER TABLE chat_threads ADD COLUMN owner_id INTEGER")

        # users: migrate the original single-provider schema (google_sub) to the
        # provider + subject shape without dropping existing rows.
        urows = conn.exec_driver_sql("PRAGMA table_info(users)").all()
        ucols = {r[1] for r in urows}
        if urows and "provider" not in ucols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN provider VARCHAR(20) DEFAULT 'google'")
        if urows and "subject" not in ucols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN subject VARCHAR(255)")
            if "google_sub" in ucols:
                conn.exec_driver_sql("UPDATE users SET subject = google_sub WHERE subject IS NULL")
        # Drop the legacy NOT NULL google_sub column so provider-agnostic inserts work.
        if "google_sub" in ucols:
            conn.exec_driver_sql("UPDATE users SET subject = google_sub WHERE subject IS NULL")
            conn.exec_driver_sql("DROP INDEX IF EXISTS ix_users_google_sub")
            conn.exec_driver_sql("ALTER TABLE users DROP COLUMN google_sub")


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
