"""
Database configuration and session management for the integration backend.

Environment variables (configure via container .env, do not hardcode):
- INTEGRATION_DB_URL: SQLAlchemy database URL.
  Example for SQLite (default if not provided): sqlite:///./integration.db
  Example for Postgres: postgresql+psycopg://user:password@host:5432/dbname
"""

from __future__ import annotations

import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session


# PUBLIC_INTERFACE
class Base(DeclarativeBase):
    """SQLAlchemy Declarative Base for all models."""


def _get_database_url() -> str:
    """Resolve database URL from environment or fallback to local SQLite file."""
    db_url = os.getenv("INTEGRATION_DB_URL")
    if not db_url or not db_url.strip():
        # Default to SQLite file within the container working directory
        db_url = "sqlite:///./integration.db"
    return db_url


DATABASE_URL = _get_database_url()

# SQLite needs check_same_thread=False when used with FastAPI/Uvicorn in threaded contexts.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, echo=False, future=True, connect_args=connect_args)

SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine, class_=Session, future=True
)


# PUBLIC_INTERFACE
def get_db() -> Generator[Session, None, None]:
    """Yield a database session for dependency injection in FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
