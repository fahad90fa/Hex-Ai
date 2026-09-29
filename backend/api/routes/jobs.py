"""Job dispatch and query routes."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_db
from backend.db.models import Job, JobStatus
from backend.shared_types import JobCreate, JobResponse

router = APIRouter()


@router.get("/jobs", response_model=list[JobResponse])
async def list_jobs(
    session_id: Optional[uuid.UUID] = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> list[JobResponse]:
    """List jobs, optionally filtered by session_id, newest first."""
    q = select(Job)
    if session_id:
        q = q.where(Job.session_id == session_id)
    q = q.order_by(Job.created_at.desc()).limit(200)
    result = await db.execute(q)
    return [_to_response(j, tail_lines=None) for j in result.scalars().all()]


@router.post("/jobs", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
async def dispatch_job(
    body: JobCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JobResponse:
    """Dispatch a tool job to the worker queue."""
    job = Job(
        id=uuid.uuid4(),
        session_id=body.session_id,
        tool_name=body.tool_name,
        status=JobStatus.QUEUED,
        params_json=body.params,
    )
    db.add(job)
    await db.flush()

    # Enqueue in orchestrator via app.state (set in lifespan)
    try:
        wp = getattr(request.app.state, "worker_pool", None)
        if wp is None:
            raise RuntimeError("Worker pool not initialised — backend may still be starting up")
        await wp.dispatch({
            "job_id": str(job.id),
            "session_id": str(body.session_id),
            "tool_name": body.tool_name,
            "params": body.params or {},
        })
    except Exception as exc:
        job.status = JobStatus.FAILED
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enqueue job: {exc}",
        )

    await db.refresh(job)
    return _to_response(job, tail_lines=None)


@router.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> JobResponse:
    """Return job status plus last 100 lines of output."""
    result = await db.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    tail_lines: list[str] | None = None
    if job.output_path and os.path.isfile(job.output_path):
        try:
            with open(job.output_path, "r", errors="replace") as fh:
                lines = fh.readlines()
                tail_lines = [l.rstrip("\n") for l in lines[-100:]]
        except OSError:
            tail_lines = None

    return _to_response(job, tail_lines=tail_lines)


@router.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def kill_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Kill a running job."""
    result = await db.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(status_code=409, detail=f"Job is already {job.status.value}")

    try:
        from backend.core.orchestrator import get_orchestrator
        await get_orchestrator().kill_job(str(job_id))
    except Exception:
        pass  # Best effort

    job.status = JobStatus.KILLED
    job.ended_at = datetime.now(timezone.utc)


def _to_response(job: Job, tail_lines: list[str] | None) -> JobResponse:
    return JobResponse(
        id=job.id,
        session_id=job.session_id,
        tool_name=job.tool_name,
        status=job.status,
        params=job.params_json,
        output_path=job.output_path,
        output_tail=tail_lines,
        started_at=job.started_at,
        ended_at=job.ended_at,
        findings_count=job.findings_count,
        created_at=job.created_at,
    )
