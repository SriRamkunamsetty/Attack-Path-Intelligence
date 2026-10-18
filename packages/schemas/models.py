"""Core Pydantic schemas and domain models for AttackPath Intelligence."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    ASSET = "asset"
    OBSERVATION = "observation"
    ATTACK_STEP = "attack_step"
    TECHNIQUE = "technique"
    SECURITY_CONTROL = "security_control"
    FINDING = "finding"


class EdgeType(str, Enum):
    PRECEDES = "PRECEDES"          # Temporal: A occurred before B, no causation implied
    ENABLES = "ENABLES"            # Causal: A made B possible by satisfying prerequisites
    OBSERVED_AS = "OBSERVED_AS"    # Evidentiary: AttackStep is backed by Observation
    MAPPED_TO = "MAPPED_TO"        # Knowledge: Step or Observation maps to ATT&CK Technique
    MITIGATED_BY = "MITIGATED_BY"  # Defensive: Control reduces feasibility or impact of Step
    CONTRADICTS = "CONTRADICTS"    # Conflict: Evidence contradicts a step or condition
    DEPENDS_ON = "DEPENDS_ON"      # Requirement: Step requires an Asset, condition, or privilege


class Severity(str, Enum):
    ERROR = "ERROR"      # Hard invariant violated (e.g. time travel, broken graph reference)
    WARNING = "WARNING"  # Plausible inconsistency or contradiction requiring investigation
    INFO = "INFO"        # Evidence gap, unverified assumption, or recommendation


class PathStatus(str, Enum):
    SUPPORTED = "supported"                      # All critical transitions backed by direct evidence
    PARTIALLY_SUPPORTED = "partially_supported"  # Some transitions supported, others rely on assumptions
    UNSUBSTANTIATED = "unsubstantiated"          # Essential transitions completely lack supporting evidence
    CONTRADICTED = "contradicted"                # Verified evidence actively conflicts with this path


class ReviewStatus(str, Enum):
    REQUIRES_REVIEW = "requires_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class AssetType(str, Enum):
    HOST = "host"
    IDENTITY = "identity"
    APPLICATION = "application"
    DATABASE = "database"
    CLOUD_RESOURCE = "cloud_resource"
    NETWORK = "network"


class ControlState(str, Enum):
    CONFIRMED_PRESENT = "confirmed_present"
    CONFIRMED_ABSENT = "confirmed_absent"
    RECOMMENDED = "recommended"
    UNKNOWN = "unknown"


# -------------------------------------------------------------------------
# Node Data Models
# -------------------------------------------------------------------------

class Asset(BaseModel):
    id: str
    name: str
    asset_type: AssetType = AssetType.HOST
    criticality: str = Field(default="medium", description="low, medium, high, critical")
    ip_addresses: List[str] = Field(default_factory=list)
    identities: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Observation(BaseModel):
    id: str
    source_id: str
    timestamp: datetime
    category: str = Field(description="auth, endpoint, network, config, alert, etc.")
    description: str
    asset_id: Optional[str] = None
    actor_identity: Optional[str] = None
    target_identity: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    provenance_hash: Optional[str] = None
    data_quality_flags: List[str] = Field(default_factory=list)


class AttackStep(BaseModel):
    id: str
    title: str
    stage: str = Field(default="execution", description="MITRE tactic or attack phase")
    description: str = ""
    asset_id: Optional[str] = None
    actor_identity: Optional[str] = None
    is_inferred: bool = Field(default=True, description="True if inferred, False if directly observed")
    status: str = Field(default="hypothesized", description="hypothesized, supported, contradicted")
    timestamp: Optional[datetime] = None
    prerequisites: List[str] = Field(default_factory=list, description="IDs of required conditions or steps")


class Technique(BaseModel):
    technique_id: str = Field(description="e.g. T1110.001")
    name: str
    tactics: List[str] = Field(default_factory=list)
    description: str = ""
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    url: Optional[str] = None
    version: str = "v15.1"


class SecurityControl(BaseModel):
    id: str
    name: str
    category: str = Field(description="preventive, detective, responsive, corrective")
    state: ControlState = ControlState.RECOMMENDED
    effectiveness_verified: bool = False
    description: str = ""
    coverage_notes: str = ""


class Finding(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    affected_node_ids: List[str] = Field(default_factory=list)
    affected_edge_ids: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list, description="IDs of supporting observations")
    explanation: str
    remediation_guidance: str = ""


# -------------------------------------------------------------------------
# Graph Model
# -------------------------------------------------------------------------

class GraphNode(BaseModel):
    id: str
    type: NodeType
    label: str
    data: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    edge_type: EdgeType
    evidence_refs: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackGraphExport(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


# -------------------------------------------------------------------------
# Candidate Paths & Reasoning
# -------------------------------------------------------------------------

class CandidatePath(BaseModel):
    path_id: str
    name: str
    step_ids: List[str]
    edge_ids: List[str]
    status: PathStatus
    confidence_rationale: str
    supporting_observations: List[str] = Field(default_factory=list)
    required_assumptions: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    conflicting_evidence: List[str] = Field(default_factory=list)
    discriminator_evidence: List[str] = Field(default_factory=list, description="Telemetry that would confirm/refute this vs competing paths")
    potential_impact: str = ""


class TechniqueMappingRecord(BaseModel):
    mapping_id: str
    target_id: str  # Observation ID or AttackStep ID
    technique_id: str
    technique_name: str
    rationale: str
    supporting_evidence: List[str]
    missing_evidence_required: List[str] = Field(default_factory=list)
    status: ReviewStatus = ReviewStatus.REQUIRES_REVIEW
    reviewer_notes: Optional[str] = None


# -------------------------------------------------------------------------
# Scenario & Ingestion Bundles
# -------------------------------------------------------------------------

class EvidenceSource(BaseModel):
    id: str
    name: str
    source_type: str = Field(description="json_bundle, csv_log, configuration, narrative")
    file_hash: str
    ingestion_timestamp: datetime
    record_count: int = 0


class Scenario(BaseModel):
    id: str
    name: str
    description: str = ""
    objective: str = ""
    created_at: datetime
    updated_at: datetime
    evidence_source_ids: List[str] = Field(default_factory=list)


class ScenarioBundle(BaseModel):
    scenario: Scenario
    assets: List[Asset] = Field(default_factory=list)
    observations: List[Observation] = Field(default_factory=list)
    hypotheses: List[AttackStep] = Field(default_factory=list)
    controls: List[SecurityControl] = Field(default_factory=list)
    explicit_edges: List[GraphEdge] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    scenario_id: str
    timestamp: datetime
    rule_engine_version: str = "1.0.0"
    dataset_version: str = "ATT&CK v15.1"
    graph: AttackGraphExport
    findings: List[Finding]
    candidate_paths: List[CandidatePath]
    technique_mappings: List[TechniqueMappingRecord] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
