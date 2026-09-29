"""NEXUS FastAPI application entry-point."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from neo4j import AsyncGraphDatabase

from backend.api.routes import (
    ai,
    findings,
    graph,
    jobs,
    reports,
    sessions,
    ws,
)
from backend.config import settings
from backend.api.routes.ws import ws_hub
from backend.core.orchestrator import WorkerPool
from backend.db.session import init_db

logger = logging.getLogger("nexus")

# Global handles (populated in lifespan)
_redis_client: aioredis.Redis | None = None
_neo4j_driver = None
_worker_pool: WorkerPool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    global _redis_client, _neo4j_driver, _worker_pool

    logger.info("Starting NEXUS backend...")

    # 1. Init database tables
    await init_db()
    logger.info("Database tables initialised.")

    # 2. Connect Redis
    _redis_client = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        max_connections=50,
    )
    await _redis_client.ping()
    app.state.redis = _redis_client
    logger.info("Redis connected.")

    # 3. Connect Neo4j
    _neo4j_driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    await _neo4j_driver.verify_connectivity()
    app.state.neo4j = _neo4j_driver
    logger.info("Neo4j connected.")

    # 4. Start worker pool
    _worker_pool = WorkerPool(n_workers=10)
    await _worker_pool.start()
    app.state.worker_pool = _worker_pool
    logger.info("Worker pool started (10 workers).")

    # 5. Start WebSocket hub Redis subscriber
    await ws_hub.start_subscriber(_redis_client)
    logger.info("WS hub subscriber started.")

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    logger.info("Shutting down NEXUS backend...")

    if _worker_pool:
        await _worker_pool.stop()

    await ws_hub.stop_subscriber()

    if _redis_client:
        await _redis_client.aclose()

    if _neo4j_driver:
        await _neo4j_driver.close()

    logger.info("Shutdown complete.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="NEXUS Penetration Testing Framework",
        version="1.0.0",
        description="AI-driven cross-platform penetration testing orchestration platform.",
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    api_prefix = "/api/v1"
    app.include_router(sessions.router, prefix=api_prefix, tags=["sessions"])
    app.include_router(jobs.router, prefix=api_prefix, tags=["jobs"])
    app.include_router(findings.router, prefix=api_prefix, tags=["findings"])
    app.include_router(reports.router, prefix=api_prefix, tags=["reports"])
    app.include_router(graph.router, prefix=api_prefix, tags=["graph"])
    app.include_router(ai.router, prefix=api_prefix, tags=["ai"])
    app.include_router(ws.router, tags=["websocket"])

    # Health check
    @app.get("/health", tags=["health"])
    async def health():
        return {"status": "ok", "version": "1.0.0"}

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=settings.backend_port,
        reload=settings.debug,
        log_level="info",
    )
