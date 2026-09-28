"""Report generation and retrieval routes."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_db
from backend.db.models import Report
from backend.shared_types import ReportCreate, ReportResponse

router = APIRouter()


@router.post("/reports/generate", response_model=ReportResponse, status_code=status.HTTP_202_ACCEPTED)
async def generate_report(
    body: ReportCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    """Trigger async report generation for a session."""
    report = Report(
        id=uuid.uuid4(),
        session_id=body.session_id,
        title=body.title or f"NEXUS Report — {body.session_id}",
        template=body.template or "technical",
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    report_id = report.id

    async def _generate():
        from backend.core.report_gen import ReportGenerator
        gen = ReportGenerator()
        await gen.generate(str(body.session_id), body.template or "technical", report_id=report_id)

    background_tasks.add_task(_generate)

    return _to_response(report)


@router.get("/reports/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    """Return report metadata and generated file paths."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return _to_response(report)


def _to_response(r: Report) -> ReportResponse:
    return ReportResponse(
        id=r.id,
        session_id=r.session_id,
        title=r.title,
        template=r.template,
        pdf_path=r.pdf_path,
        html_path=r.html_path,
        created_at=r.created_at,
    )
