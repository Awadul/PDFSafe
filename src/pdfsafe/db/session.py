"""Async (API) and sync (Celery / Alembic) session factories."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from functools import lru_cache
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from pdfsafe.config import Settings, get_settings


def _engine_kwargs(settings: Settings) -> dict[str, Any]:
    if settings.database_url.startswith("sqlite"):
        # SQLite (tests) does not support pool sizing.
        return {"echo": settings.database_echo, "poolclass": NullPool}
    return {
        "echo": settings.database_echo,
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_max_overflow,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    """Cached async engine (API process)."""
    settings = get_settings()
    return create_async_engine(settings.database_url, **_engine_kwargs(settings))


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a transactional session."""
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Async context manager for use outside the request cycle."""
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# --------------------------------------------------------------------------
# Synchronous side (Celery workers, Alembic, CLI)
# --------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_sync_engine() -> Engine:
    settings = get_settings()
    return create_engine(settings.sync_database_url, **_engine_kwargs(settings))


@lru_cache(maxsize=1)
def get_sync_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_sync_engine(), expire_on_commit=False, autoflush=False)


@contextmanager
def sync_session_scope() -> Iterator[Session]:
    """Transactional scope for worker code."""
    factory = get_sync_sessionmaker()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


async def dispose_engine() -> None:
    """Close pooled connections on shutdown."""
    engine = get_engine()
    await engine.dispose()
