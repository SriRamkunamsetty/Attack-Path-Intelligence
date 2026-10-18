"""SQLAlchemy 2.0 ORM Models for AttackPath Intelligence durable storage."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


class ProjectModel(Base):
    """Analysis workspace and tenant ownership."""
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default-tenant", index=True)
    owner: Mapped[str] = mapped_column(String(128), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    scenarios: Mapped[List[ScenarioModel]] = relationship(back_populates="project", cascade="all, delete-orphan")


class ScenarioModel(Base):
    """Analysis scenario metadata and objective."""
    __tablename__ = "attack_scenarios"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    objective: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    project: Mapped[Optional[ProjectModel]] = relationship(back_populates="scenarios")
    assets: Mapped[List[AssetModel]] = relationship(back_populates="scenario", cascade="all, delete-orphan")
    observations: Mapped[List[ObservationModel]] = relationship(back_populates="scenario", cascade="all, delete-orphan")
    graph_nodes: Mapped[List[GraphNodeModel]] = relationship(back_populates="scenario", cascade="all, delete-orphan")
    graph_edges: Mapped[List[GraphEdgeModel]] = relationship(back_populates="scenario", cascade="all, delete-orphan")
    findings: Mapped[List[ValidationFindingModel]] = relationship(back_populates="scenario", cascade="all, delete-orphan")
    analysis_runs: Mapped[List[AnalysisRunModel]] = relationship(back_populates="scenario", cascade="all, delete-orphan")


class AssetModel(Base):
    """Asset entities (hosts, identities, apps, databases, cloud)."""
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), ForeignKey("attack_scenarios.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), default="host")
    criticality: Mapped[str] = mapped_column(String(32), default="medium")
    ip_addresses: Mapped[List[str]] = mapped_column(JSON, default=list)
    identities: Mapped[List[str]] = mapped_column(JSON, default=list)
    attributes: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    scenario: Mapped[ScenarioModel] = relationship(back_populates="assets")


class EvidenceSourceModel(Base):
    """Provenance and source file metadata."""
    __tablename__ = "evidence_sources"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), ForeignKey("attack_scenarios.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), default="json_bundle")
    file_hash: Mapped[str] = mapped_column(String(64), index=True)
    ingestion_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    record_count: Mapped[int] = mapped_column(Integer, default=0)


class ObservationModel(Base):
    """Normalized empirical security observations."""
    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), ForeignKey("attack_scenarios.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    actor_identity: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    target_identity: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    raw_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    provenance_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    data_quality_flags: Mapped[List[str]] = mapped_column(JSON, default=list)

    scenario: Mapped[ScenarioModel] = relationship(back_populates="observations")


class GraphNodeModel(Base):
    """Persisted graph node records."""
    __tablename__ = "graph_nodes"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), ForeignKey("attack_scenarios.id", ondelete="CASCADE"), primary_key=True, index=True)
    node_type: Mapped[str] = mapped_column(String(64), index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    scenario: Mapped[ScenarioModel] = relationship(back_populates="graph_nodes")


class GraphEdgeModel(Base):
    """Persisted graph directed edges with evidence links."""
    __tablename__ = "graph_edges"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), ForeignKey("attack_scenarios.id", ondelete="CASCADE"), primary_key=True, index=True)
    source: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str] = mapped_column(String(128), index=True)
    edge_type: Mapped[str] = mapped_column(String(64), index=True)
    evidence_refs: Mapped[List[str]] = mapped_column(JSON, default=list)
    metadata_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    scenario: Mapped[ScenarioModel] = relationship(back_populates="graph_edges")


class ValidationFindingModel(Base):
    """Deterministic validation rule outputs and remediation advice."""
    __tablename__ = "validation_findings"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), ForeignKey("attack_scenarios.id", ondelete="CASCADE"), primary_key=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_name: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(32), index=True)
    affected_node_ids: Mapped[List[str]] = mapped_column(JSON, default=list)
    affected_edge_ids: Mapped[List[str]] = mapped_column(JSON, default=list)
    evidence_refs: Mapped[List[str]] = mapped_column(JSON, default=list)
    explanation: Mapped[str] = mapped_column(Text)
    remediation_guidance: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scenario: Mapped[ScenarioModel] = relationship(back_populates="findings")


class ControlMappingModel(Base):
    """Defensive security controls and association with attack steps."""
    __tablename__ = "control_mappings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), ForeignKey("attack_scenarios.id", ondelete="CASCADE"), index=True)
    step_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(64))
    effectiveness_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = mapped_column(Text, default="")


class AnalysisRunModel(Base):
    """Audit record of an execution run of the reasoning engine."""
    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), ForeignKey("attack_scenarios.id", ondelete="CASCADE"), index=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    rule_engine_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    dataset_version: Mapped[str] = mapped_column(String(32), default="ATT&CK v15.1")
    metrics: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    candidate_paths_json: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="completed")

    scenario: Mapped[ScenarioModel] = relationship(back_populates="analysis_runs")


class ReviewDecisionModel(Base):
    """Human analyst authorization, validation, and review tracking."""
    __tablename__ = "review_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(128), index=True)
    decision: Mapped[str] = mapped_column(String(32))  # requires_review, accepted, rejected
    reviewer: Mapped[str] = mapped_column(String(128))
    rationale: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
