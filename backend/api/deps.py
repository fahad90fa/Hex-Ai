"""FastAPI dependency injection helpers."""
from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Optional

import redis.asyncio as aioredis
from fastapi import Depends, Header, HTTPException, Request, status
from neo4j import AsyncDriver
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import AsyncSessionLocal


# ─── Database ──────────────────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session, commit on success, rollback on failure."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ─── Redis ─────────────────────────────────────────────────────────────────────

async def get_redis(request: Request) -> aioredis.Redis:
    """Return the application-wide Redis client."""
    return request.app.state.redis


# ─── Neo4j ─────────────────────────────────────────────────────────────────────

async def get_neo4j(request: Request) -> AsyncDriver:
    """Return the application-wide Neo4j async driver."""
    return request.app.state.neo4j


# ─── Current Session ───────────────────────────────────────────────────────────

async def get_current_session_id(
    x_session_id: Optional[str] = Header(default=None, alias="X-Session-ID"),
) -> Optional[uuid.UUID]:
    """
    Read an optional session UUID from the X-Session-ID request header.
    Returns None when the header is absent (some endpoints don't require it).
    """
    if x_session_id is None:
        return None
    try:
        return uuid.UUID(x_session_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Session-ID header — must be a valid UUID.",
        )


async def require_session_id(
    session_id: Optional[uuid.UUID] = Depends(get_current_session_id),
) -> uuid.UUID:
    """Like get_current_session_id but raises 400 if the header is missing."""
    if session_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Session-ID header is required.",
        )
    return session_id
