"""AI brain routes — planning, analysis, decision history."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_db, get_redis

router = APIRouter()


@router.post("/ai/plan")
async def trigger_ai_plan(
    session_id: uuid.UUID,
    target: str,
    background_tasks: BackgroundTasks,
) -> dict:
    """Trigger AI attack planning for a session."""

    async def _plan():
        from backend.ai.brain import run_session
        await run_session(str(session_id), target)

    background_tasks.add_task(_plan)
    return {"status": "planning_started", "session_id": str(session_id)}


@router.post("/ai/analyze")
async def analyze_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Request AI analysis of a specific finding."""
    from sqlalchemy import select
    from backend.db.models import Finding

    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Finding not found")

    import anthropic
    from backend.config import settings

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    prompt = (
        f"Analyze the following security finding and provide:\n"
        f"1. Root cause analysis\n"
        f"2. Exploitation difficulty (Low/Medium/High)\n"
        f"3. Business impact\n"
        f"4. Step-by-step remediation\n\n"
        f"Finding Title: {finding.title}\n"
        f"Severity: {finding.severity.value}\n"
        f"Affected Asset: {finding.affected_asset or 'Unknown'}\n"
        f"Description: {finding.description or 'N/A'}\n"
        f"Evidence: {finding.evidence or 'N/A'}\n"
        f"CVEs: {', '.join(finding.cve_ids or []) or 'None'}\n"
    )

    message = await client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )
    analysis_text = message.content[0].text

    return {
        "finding_id": str(finding_id),
        "analysis": analysis_text,
        "model": "claude-3-5-sonnet-20241022",
    }


@router.get("/ai/decisions")
async def get_ai_decisions(
    session_id: uuid.UUID = Query(...),
    redis=Depends(get_redis),
) -> dict:
    """Return AI decision history for a session from Redis."""
    key = f"session:{session_id}:ai_decisions"
    raw_decisions = await redis.lrange(key, 0, 99)  # Last 100 decisions

    import json
    decisions = []
    for raw in raw_decisions:
        try:
            decisions.append(json.loads(raw))
        except Exception:
            decisions.append({"raw": raw})

    return {
        "session_id": str(session_id),
        "decisions": decisions,
        "count": len(decisions),
    }
