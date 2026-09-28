"""WebSocket event types and Pydantic models for real-time NEXUS events."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, Field


# ─── Event Type Enum ──────────────────────────────────────────────────────────

class EventType(str, Enum):
    JOB_STARTED = "job.started"
    JOB_OUTPUT = "job.output"
    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    FINDING_NEW = "finding.new"
    GRAPH_NODE_ADDED = "graph.node_added"
    GRAPH_EDGE_ADDED = "graph.edge_added"
    AI_DECISION = "ai.decision"
    CVE_MATCH = "cve.match"
    PAYLOAD_EVASION = "payload.evasion"
    REPORT_READY = "report.ready"
    SESSION_STARTED = "session.started"
    SESSION_COMPLETED = "session.completed"
    SESSION_FAILED = "session.failed"
    PHASE_CHANGED = "phase.changed"
    ANOMALY_DETECTED = "anomaly.detected"


# ─── Base Event ───────────────────────────────────────────────────────────────

class BaseEvent(BaseModel):
    type: str
    session_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ─── Job Events ───────────────────────────────────────────────────────────────

class JobStartedEvent(BaseEvent):
    type: Literal["job.started"] = "job.started"
    data: dict = Field(default_factory=dict)
    # data: {job_id, tool_name, params}


class JobOutputEvent(BaseEvent):
    type: Literal["job.output"] = "job.output"
    data: dict = Field(default_factory=dict)
    # data: {job_id, line}


class JobCompletedEvent(BaseEvent):
    type: Literal["job.completed"] = "job.completed"
    data: dict = Field(default_factory=dict)
    # data: {job_id, findings_count, duration_ms}


class JobFailedEvent(BaseEvent):
    type: Literal["job.failed"] = "job.failed"
    data: dict = Field(default_factory=dict)
    # data: {job_id, error}


# ─── Finding Events ───────────────────────────────────────────────────────────

class FindingNewEvent(BaseEvent):
    type: Literal["finding.new"] = "finding.new"
    data: dict = Field(default_factory=dict)
    # data: {id, title, severity, cvss_score, affected_asset, cve_ids}


# ─── Graph Events ─────────────────────────────────────────────────────────────

class GraphNodeAddedEvent(BaseEvent):
    type: Literal["graph.node_added"] = "graph.node_added"
    data: dict = Field(default_factory=dict)
    # data: {id, label, type, properties}


class GraphEdgeAddedEvent(BaseEvent):
    type: Literal["graph.edge_added"] = "graph.edge_added"
    data: dict = Field(default_factory=dict)
    # data: {source_id, target_id, relationship, confidence}


# ─── AI Events ────────────────────────────────────────────────────────────────

class AIDecisionEvent(BaseEvent):
    type: Literal["ai.decision"] = "ai.decision"
    data: dict = Field(default_factory=dict)
    # data: {node, tool, reasoning, confidence, job_id}


# ─── CVE/Exploit Events ───────────────────────────────────────────────────────

class CveMatchEvent(BaseEvent):
    type: Literal["cve.match"] = "cve.match"
    data: dict = Field(default_factory=dict)
    # data: {cve_id, service, severity, has_exploit, exploitable}


class PayloadEvasionEvent(BaseEvent):
    type: Literal["payload.evasion"] = "payload.evasion"
    data: dict = Field(default_factory=dict)
    # data: {iteration, av_score, payload_path, mutation_type}


# ─── Report Events ────────────────────────────────────────────────────────────

class ReportReadyEvent(BaseEvent):
    type: Literal["report.ready"] = "report.ready"
    data: dict = Field(default_factory=dict)
    # data: {html_path, pdf_path, findings_count, executive_summary_preview}


# ─── Session Events ───────────────────────────────────────────────────────────

class SessionStartedEvent(BaseEvent):
    type: Literal["session.started"] = "session.started"
    data: dict = Field(default_factory=dict)


class SessionCompletedEvent(BaseEvent):
    type: Literal["session.completed"] = "session.completed"
    data: dict = Field(default_factory=dict)


class SessionFailedEvent(BaseEvent):
    type: Literal["session.failed"] = "session.failed"
    data: dict = Field(default_factory=dict)


# ─── Phase Event ──────────────────────────────────────────────────────────────

class PhaseChangedEvent(BaseEvent):
    type: Literal["phase.changed"] = "phase.changed"
    data: dict = Field(default_factory=dict)
    # data: {old_phase, new_phase}


class AnomalyDetectedEvent(BaseEvent):
    type: Literal["anomaly.detected"] = "anomaly.detected"
    data: dict = Field(default_factory=dict)
    # data: {type, description, severity}


# ─── Union discriminator ──────────────────────────────────────────────────────

WSEvent = Annotated[
    Union[
        JobStartedEvent,
        JobOutputEvent,
        JobCompletedEvent,
        JobFailedEvent,
        FindingNewEvent,
        GraphNodeAddedEvent,
        GraphEdgeAddedEvent,
        AIDecisionEvent,
        CveMatchEvent,
        PayloadEvasionEvent,
        ReportReadyEvent,
        SessionStartedEvent,
        SessionCompletedEvent,
        SessionFailedEvent,
        PhaseChangedEvent,
        AnomalyDetectedEvent,
    ],
    Field(discriminator="type"),
]
