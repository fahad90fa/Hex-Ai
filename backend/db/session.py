"""Async SQLAlchemy engine and session factory."""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from typing import AsyncGenerator as AG

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.db.models import Base

# ─── Engine ────────────────────────────────────────────────────────────────────

_DATABASE_URL: str = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://nexus:nexus_pass@localhost:5432/nexus_db"
)

engine: AsyncEngine = create_async_engine(
    _DATABASE_URL,
    echo=False,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ─── Dependency ────────────────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ─── Initialisation ────────────────────────────────────────────────────────────

async def init_db() -> None:
    """Create all tables defined in the ORM models (idempotent)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
