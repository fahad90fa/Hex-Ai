"""SQLAlchemy 2.0 async ORM models for NEXUS."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ─── Enumerations ──────────────────────────────────────────────────────────────

class SessionStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class JobStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    KILLED = "KILLED"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class NodeType(str, enum.Enum):
    SUBDOMAIN = "SUBDOMAIN"
    ENDPOINT = "ENDPOINT"
    SERVICE = "SERVICE"
    CREDENTIAL = "CREDENTIAL"
    USER = "USER"


# ─── Models ────────────────────────────────────────────────────────────────────

class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[SessionStatus] = mapped_column(
        Enum(SessionStatus), nullable=False, default=SessionStatus.PENDING
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    config_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    jobs: Mapped[list[Job]] = relationship("Job", back_populates="session", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="session", cascade="all, delete-orphan")
    credentials: Mapped[list[Credential]] = relationship("Credential", back_populates="session", cascade="all, delete-orphan")
    reports: Mapped[list[Report]] = relationship("Report", back_populates="session", cascade="all, delete-orphan")
    graph_nodes: Mapped[list[GraphNode]] = relationship("GraphNode", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_sessions_status", "status"),
        Index("ix_sessions_created_at", "created_at"),
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus), nullable=False, default=JobStatus.QUEUED
    )
    params_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    output_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    session: Mapped[Session] = relationship("Session", back_populates="jobs")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="job")

    __table_args__ = (
        Index("ix_jobs_session_id", "session_id"),
        Index("ix_jobs_status", "status"),
        Index("ix_jobs_tool_name", "tool_name"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity), nullable=False, default=Severity.INFO
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    poc_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    cve_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)
    affected_asset: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    session: Mapped[Session] = relationship("Session", back_populates="findings")
    job: Mapped[Optional[Job]] = relationship("Job", back_populates="findings")

    __table_args__ = (
        UniqueConstraint("session_id", "dedup_hash", name="uq_finding_session_hash"),
        Index("ix_findings_session_id", "session_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_dedup_hash", "dedup_hash"),
    )


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    host: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    password_hash: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    hash_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cracked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    plaintext: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    session: Mapped[Session] = relationship("Session", back_populates="credentials")

    __table_args__ = (
        Index("ix_credentials_session_id", "session_id"),
        Index("ix_credentials_host_port", "host", "port"),
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    template: Mapped[str] = mapped_column(String(64), nullable=False, default="technical")
    pdf_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    html_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    session: Mapped[Session] = relationship("Session", back_populates="reports")

    __table_args__ = (Index("ix_reports_session_id", "session_id"),)


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[NodeType] = mapped_column(Enum(NodeType), nullable=False)
    label: Mapped[str] = mapped_column(String(512), nullable=False)
    properties_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    session: Mapped[Session] = relationship("Session", back_populates="graph_nodes")
    outgoing_edges: Mapped[list[GraphEdge]] = relationship(
        "GraphEdge", foreign_keys="GraphEdge.source_node_id", back_populates="source_node",
        cascade="all, delete-orphan"
    )
    incoming_edges: Mapped[list[GraphEdge]] = relationship(
        "GraphEdge", foreign_keys="GraphEdge.target_node_id", back_populates="target_node",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_graph_nodes_session_id", "session_id"),
        Index("ix_graph_nodes_type", "type"),
        Index("ix_graph_nodes_label", "label"),
    )


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    target_node_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    rel_type: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    source_node: Mapped[GraphNode] = relationship(
        "GraphNode", foreign_keys="[GraphEdge.source_node_id]", back_populates="outgoing_edges"
    )
    target_node: Mapped[GraphNode] = relationship(
        "GraphNode", foreign_keys="[GraphEdge.target_node_id]", back_populates="incoming_edges"
    )

    __table_args__ = (
        Index("ix_graph_edges_source_node_id", "source_node_id"),
        Index("ix_graph_edges_target_node_id", "target_node_id"),
        Index("ix_graph_edges_rel_type", "rel_type"),
    )
