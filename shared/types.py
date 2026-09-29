"""Complete Pydantic v2 models for the NEXUS API."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


# ─── Enumerations ─────────────────────────────────────────────────

class SessionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    KILLED = "KILLED"
    CANCELLED = "CANCELLED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class NodeType(str, Enum):
    TARGET = "TARGET"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    PORT = "PORT"
    SERVICE = "SERVICE"
    ENDPOINT = "ENDPOINT"
    VULNERABILITY = "VULNERABILITY"
    CREDENTIAL = "CREDENTIAL"
    USER = "USER"
    SHARE = "SHARE"


class ToolCategory(str, Enum):
    RECON = "RECON"
    SCAN = "SCAN"
    WEB = "WEB"
    AUTH = "AUTH"
    EXPLOIT = "EXPLOIT"
    REVERSING = "REVERSING"
    NETWORK = "NETWORK"


# ─── Session ───────────────────────────────────────────────────

class SessionCreate(BaseModel):
    target: str = Field(..., description="Target domain, IP, or CIDR range")
    config: dict[str, Any] = Field(default_factory=dict, description="Session configuration")


class SessionResponse(BaseModel):
    id: uuid.UUID
    target: str
    status: SessionStatus
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    config: dict[str, Any] = Field(default_factory=dict)
    findings_count: int = 0
    jobs_count: int = 0
    coverage_pct: Optional[float] = None

    model_config = {"from_attributes": True}


# ─── Jobs ──────────────────────────────────────────────────────

class JobCreate(BaseModel):
    session_id: uuid.UUID
    tool_name: str
    params: dict[str, Any] = Field(default_factory=dict)


class JobResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    tool_name: str
    status: JobStatus
    params: dict[str, Any] = Field(default_factory=dict)
    output_path: Optional[str] = None
    output_tail: Optional[list[str]] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    findings_count: int = 0

    model_config = {"from_attributes": True}


# ─── Findings ───────────────────────────────────────────────────

class FindingCreate(BaseModel):
    session_id: uuid.UUID
    job_id: Optional[uuid.UUID] = None
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    evidence: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    affected_asset: str = ""
    remediation: str = ""
    poc_path: str = ""


class FindingResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    job_id: Optional[uuid.UUID] = None
    title: str
    description: str = ""
    severity: Severity
    cvss_score: Optional[float] = None
    evidence: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    affected_asset: str = ""
    remediation: str = ""
    poc_path: str = ""
    dedup_hash: str = ""
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[Severity] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    remediation: Optional[str] = None


# ─── Reports ───────────────────────────────────────────────────

class ReportCreate(BaseModel):
    session_id: uuid.UUID
    title: str = "NEXUS Penetration Test Report"
    template: str = Field(default="technical", description="executive|technical|bug_bounty")


class ReportResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    title: str
    template: str
    pdf_path: str = ""
    html_path: str = ""
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ─── Graph ──────────────────────────────────────────────────────

class GraphNodeResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    type: NodeType
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)
    discovered_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class GraphEdgeResponse(BaseModel):
    id: uuid.UUID
    source_node_id: uuid.UUID
    target_node_id: uuid.UUID
    relationship: str
    confidence: float = 1.0

    model_config = {"from_attributes": True}


# ─── AI ──────────────────────────────────────────────────────────

class AIDecisionResponse(BaseModel):
    node: str
    tool: Optional[str] = None
    reasoning: str = ""
    confidence: float = 0.0
    timestamp: Optional[datetime] = None

    model_config = {"from_attributes": True}
