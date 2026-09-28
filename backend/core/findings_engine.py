# language: Python, file: backend/core/findings_engine.py
# FindingsEngine: ingest(), dedup by hash, CVSS rule-based scoring, DB storage, broadcast finding.new
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

from ..db.session import get_async_session
from ..tools.base import Finding, Severity

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)
_findings_engine: "FindingsEngine | None" = None


_SEVERITY_CVSS_MAP = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH: (7.0, 8.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.LOW: (0.1, 3.9),
    Severity.INFO: (0.0, 0.0),
}


def _rule_based_cvss(finding: Finding) -> float:
    """Assign a CVSS score based on severity and evidence keywords."""
    if finding.cvss_score is not None:
        return float(finding.cvss_score)

    sev = finding.severity
    base_ranges = _SEVERITY_CVSS_MAP.get(sev, (0.0, 0.0))
    base = (base_ranges[0] + base_ranges[1]) / 2.0 if base_ranges[1] > 0 else 0.0

    # Boost score if evidence contains high-impact keywords
    evidence_lower = (finding.evidence + " " + finding.description).lower()
    if any(k in evidence_lower for k in ["rce", "remote code execution", "unauthenticated", "no auth"]):
        base = min(10.0, base + 1.0)
    if any(k in evidence_lower for k in ["credentials", "password", "root", "admin"]):
        base = min(10.0, base + 0.5)
    if any(k in evidence_lower for k in ["plaintext", "cleartext", "unencrypted"]):
        base = min(10.0, base + 0.3)

    return round(base, 1)


class FindingsEngine:
    async def ingest(self, session_id: str, job_id: str, findings: list[Finding]) -> list[str]:
        """
        Ingest a list of Finding objects.
        Deduplicates by hash(session_id + title + affected_asset).
        Assigns CVSS scores via rule-based scoring.
        Stores in DB.
        Broadcasts finding.new events.
        Returns list of inserted finding IDs.
        """
        inserted_ids: list[str] = []

        async for db in get_async_session():
            for finding in findings:
                try:
                    dedup_hash = finding.dedup_key(session_id)
                    cvss = _rule_based_cvss(finding)
                    finding_id = str(uuid.uuid4())

                    # Check for duplicate
                    row = await db.execute(
                        text("SELECT id FROM findings WHERE dedup_hash = :h LIMIT 1"),
                        {"h": dedup_hash},
                    )
                    existing = row.fetchone()
                    if existing:
                        logger.debug(f"dedup skip: {finding.title[:60]}")
                        continue

                    # Insert finding
                    await db.execute(
                        text(
                            "INSERT INTO findings "
                            "(id, session_id, job_id, title, description, severity, cvss_score, "
                            "evidence, cve_ids, affected_asset, remediation, poc_path, dedup_hash, created_at) "
                            "VALUES (:id, :session_id, :job_id, :title, :description, :severity, :cvss_score, "
                            ":evidence, :cve_ids, :affected_asset, :remediation, :poc_path, :dedup_hash, :created_at)"
                        ),
                        {
                            "id": finding_id,
                            "session_id": session_id,
                            "job_id": job_id,
                            "title": finding.title[:500],
                            "description": finding.description[:5000],
                            "severity": finding.severity.value,
                            "cvss_score": cvss,
                            "evidence": finding.evidence[:5000],
                            "cve_ids": ",".join(finding.cve_ids),
                            "affected_asset": finding.affected_asset[:500],
                            "remediation": finding.remediation[:5000],
                            "poc_path": finding.poc_path[:1000],
                            "dedup_hash": dedup_hash,
                            "created_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                    await db.commit()
                    inserted_ids.append(finding_id)

                    # Broadcast finding.new
                    try:
                        from .ws_hub import get_hub
                        hub = get_hub()
                        await hub.broadcast(session_id, "finding.new", {
                            "id": finding_id,
                            "title": finding.title,
                            "severity": finding.severity.value,
                            "cvss_score": cvss,
                            "affected_asset": finding.affected_asset,
                            "cve_ids": finding.cve_ids,
                        })
                    except Exception as e:
                        logger.error(f"finding.new broadcast error: {e}")

                except Exception as e:
                    logger.error(f"findings ingest error for '{finding.title}': {e}")
                    await db.rollback()

        return inserted_ids


def get_findings_engine() -> FindingsEngine:
    global _findings_engine
    if _findings_engine is None:
        _findings_engine = FindingsEngine()
    return _findings_engine
