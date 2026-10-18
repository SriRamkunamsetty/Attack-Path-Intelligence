"""Benchmark schema models for versioned evaluation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from packages.schemas.models import PathStatus, ScenarioBundle


class BenchmarkGroundTruth(BaseModel):
    expected_edge_ids: List[str] = Field(default_factory=list)
    expected_path_status: PathStatus
    expected_finding_rule_ids: List[str] = Field(default_factory=list)
    expected_technique_ids: List[str] = Field(default_factory=list)
    has_contradiction: bool = False
    rationale: str = ""


class BenchmarkScenario(BaseModel):
    id: str
    title: str
    category: str = Field(description="golden_path, contradiction, prerequisite_gap, ambiguous_admin, etc.")
    description: str
    bundle: ScenarioBundle
    ground_truth: BenchmarkGroundTruth


class ScenarioScore(BaseModel):
    scenario_id: str
    category: str
    status_matched: bool
    predicted_status: PathStatus
    expected_status: PathStatus
    findings_matched: bool
    detected_rules: List[str]
    expected_rules: List[str]
    contradiction_matched: bool
    runtime_ms: float
    notes: str = ""


class BenchmarkScorecard(BaseModel):
    version: str = "1.0.0"
    total_scenarios: int
    passed_scenarios: int
    edge_precision: float
    edge_recall: float
    path_validity_rate: float
    unsupported_claim_rate: float
    contradiction_detection_rate: float
    attack_mapping_precision: float
    evidence_traceability_rate: float
    mean_runtime_ms: float
    category_breakdown: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    scenario_scores: List[ScenarioScore] = Field(default_factory=list)
