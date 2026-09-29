"""Session management routes."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_db
from backend.db.models import Finding, Job, Session, SessionStatus
from backend.shared_types import SessionCreate, SessionResponse

router = APIRouter()


@router.post("/sessions", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
async def create_session(
    body: SessionCreate,
    db: AsyncSession = Depends(get_db),
) -> SessionResponse:
    """Create a new pentest session and trigger AI brain planning."""
    session = Session(
        id=uuid.uuid4(),
        target=body.target,
        status=SessionStatus.PENDING,
        config_json=body.config,
    )
    db.add(session)
    await db.flush()  # get the ID assigned

    # Trigger AI brain asynchronously (fire-and-forget via background task)
    try:
        from backend.core.orchestrator import worker_pool
        from backend.ai.brain import run_session

        import asyncio
        asyncio.create_task(run_session(str(session.id), body.target))
    except Exception:
        # Non-fatal: session created, planning can be retried via /ai/plan
        pass

    await db.refresh(session)
    return _to_response(session, jobs_count=0, findings_count=0)


@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> SessionResponse:
    """Return session details with aggregated statistics."""
    result = await db.execute(select(Session).where(Session.id == session_id))
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    jobs_count_result = await db.execute(
        select(func.count(Job.id)).where(Job.session_id == session_id)
    )
    jobs_count: int = jobs_count_result.scalar_one() or 0

    findings_count_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.session_id == session_id)
    )
    findings_count: int = findings_count_result.scalar_one() or 0

    return _to_response(session, jobs_count=jobs_count, findings_count=findings_count)


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Stop and remove a session (cascades to jobs, findings, etc.)."""
    result = await db.execute(select(Session).where(Session.id == session_id))
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    # Mark running jobs as killed
    running_jobs_result = await db.execute(
        select(Job).where(Job.session_id == session_id, Job.status == "RUNNING")
    )
    for job in running_jobs_result.scalars().all():
        job.status = "KILLED"
        job.ended_at = datetime.now(timezone.utc)

    session.status = SessionStatus.FAILED
    session.ended_at = datetime.now(timezone.utc)
    await db.delete(session)


def _to_response(
    session: Session,
    jobs_count: int,
    findings_count: int,
) -> SessionResponse:
    return SessionResponse(
        id=session.id,
        target=session.target,
        status=session.status,
        started_at=session.started_at,
        ended_at=session.ended_at,
        config=session.config_json,
        jobs_count=jobs_count,
        findings_count=findings_count,
        created_at=session.created_at,
    )
