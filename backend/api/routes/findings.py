"""Findings CRUD routes."""
from __future__ import annotations

import hashlib
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_db
from backend.db.models import Finding, Severity
from backend.shared_types import FindingCreate, FindingResponse, FindingUpdate

router = APIRouter()


@router.get("/findings", response_model=list[FindingResponse])
async def list_findings(
    session_id: Optional[uuid.UUID] = Query(default=None),
    severity: Optional[Severity] = Query(default=None),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0),
    db: AsyncSession = Depends(get_db),
) -> list[FindingResponse]:
    """List findings with optional session_id and severity filters."""
    q = select(Finding)
    if session_id:
        q = q.where(Finding.session_id == session_id)
    if severity:
        q = q.where(Finding.severity == severity)
    q = q.order_by(Finding.created_at.desc()).offset(offset).limit(limit)

    result = await db.execute(q)
    return [_to_response(f) for f in result.scalars().all()]


@router.post("/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
async def create_finding(
    body: FindingCreate,
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    """Manually create a finding."""
    dedup_hash = _compute_hash(body.session_id, body.title, body.affected_asset or "")

    # Dedup check
    existing = await db.execute(
        select(Finding).where(
            Finding.session_id == body.session_id,
            Finding.dedup_hash == dedup_hash,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Duplicate finding for this session")

    finding = Finding(
        id=uuid.uuid4(),
        session_id=body.session_id,
        job_id=body.job_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        cvss_score=body.cvss_score,
        evidence=body.evidence,
        poc_path=body.poc_path,
        cve_ids=body.cve_ids or [],
        affected_asset=body.affected_asset,
        remediation=body.remediation,
        dedup_hash=dedup_hash,
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return _to_response(finding)


@router.put("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    body: FindingUpdate,
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    """Update a finding's fields."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(finding, field, value)

    await db.flush()
    await db.refresh(finding)
    return _to_response(finding)


@router.delete("/findings/{finding_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    await db.delete(finding)


def _compute_hash(session_id: uuid.UUID, title: str, affected_asset: str) -> str:
    raw = f"{session_id}:{title}:{affected_asset}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _to_response(f: Finding) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        session_id=f.session_id,
        job_id=f.job_id,
        title=f.title,
        description=f.description,
        severity=f.severity,
        cvss_score=f.cvss_score,
        evidence=f.evidence,
        poc_path=f.poc_path,
        cve_ids=f.cve_ids or [],
        affected_asset=f.affected_asset,
        remediation=f.remediation,
        dedup_hash=f.dedup_hash,
        created_at=f.created_at,
    )
