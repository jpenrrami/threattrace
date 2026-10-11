from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from threattrace.common import get_logger
from threattrace.config.settings import get_settings

settings = get_settings()
logger = get_logger(__name__)


engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_timeout=settings.db_pool_timeout_seconds,
    pool_use_lifo=settings.db_pool_use_lifo,
    pool_recycle=3600,
    future=True,
)


SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


def get_session() -> Session:
    return SessionLocal()


def get_session_factory() -> sessionmaker[Session]:
    return SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    from threattrace.db.schema import initialize_database

    initialize_database()


def check_db_health() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error(
            "Database health check failed",
            extra={"error": str(exc)},
        )
        return False
