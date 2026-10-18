"""Durable repository pattern implementation for AttackPath Intelligence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from packages.database.models import (
    AnalysisRunModel,
    AssetModel,
    EvidenceSourceModel,
    GraphEdgeModel,
    GraphNodeModel,
    ObservationModel,
    ReviewDecisionModel,
    ScenarioModel,
    ValidationFindingModel,
)
from packages.schemas.models import (
    AnalysisResult,
    Asset,
    AttackGraphExport,
    CandidatePath,
    Finding,
    GraphEdge,
    GraphNode,
    Observation,
    ReviewStatus,
    Scenario,
    ScenarioBundle,
    Severity,
)


class AttackPathRepository:
    """Manages database persistence for scenarios, evidence, graph components, and runs."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_or_update_scenario(self, scen: Scenario, project_id: Optional[str] = None) -> ScenarioModel:
        db_scen = self.db.query(ScenarioModel).filter(ScenarioModel.id == scen.id).first()
        if not db_scen:
            db_scen = ScenarioModel(
                id=scen.id,
                project_id=project_id,
                name=scen.name,
                description=scen.description,
                objective=scen.objective,
                created_at=scen.created_at,
                updated_at=scen.updated_at,
            )
            self.db.add(db_scen)
        else:
            db_scen.name = scen.name
            db_scen.description = scen.description
            db_scen.objective = scen.objective
            db_scen.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(db_scen)
        return db_scen

    def get_scenario(self, scenario_id: str) -> Optional[ScenarioModel]:
        return self.db.query(ScenarioModel).filter(ScenarioModel.id == scenario_id).first()

    def list_scenarios(self) -> List[ScenarioModel]:
        return self.db.query(ScenarioModel).order_by(ScenarioModel.created_at.desc()).all()

    def save_bundle(self, bundle: ScenarioBundle) -> None:
        scen_id = bundle.scenario.id
        self.create_or_update_scenario(bundle.scenario)

        # Clear existing observations and assets for clean idempotent replacement
        self.db.query(AssetModel).filter(AssetModel.scenario_id == scen_id).delete()
        self.db.query(ObservationModel).filter(ObservationModel.scenario_id == scen_id).delete()

        for a in bundle.assets:
            self.db.add(
                AssetModel(
                    id=a.id,
                    scenario_id=scen_id,
                    name=a.name,
                    asset_type=a.asset_type.value,
                    criticality=a.criticality,
                    ip_addresses=a.ip_addresses,
                    identities=a.identities,
                    attributes=a.attributes,
                )
            )

        for o in bundle.observations:
            self.db.add(
                ObservationModel(
                    id=o.id,
                    scenario_id=scen_id,
                    source_id=o.source_id,
                    timestamp=o.timestamp,
                    category=o.category,
                    description=o.description,
                    asset_id=o.asset_id,
                    actor_identity=o.actor_identity,
                    target_identity=o.target_identity,
                    raw_payload=o.raw_payload,
                    provenance_hash=o.provenance_hash,
                    data_quality_flags=o.data_quality_flags,
                )
            )
        self.db.commit()

    @staticmethod
    def _sanitize(obj: Any) -> Any:
        return json.loads(json.dumps(obj, default=str))

    def save_analysis_result(self, result: AnalysisResult) -> None:
        scen_id = result.scenario_id

        # Save graph nodes & edges
        self.db.query(GraphNodeModel).filter(GraphNodeModel.scenario_id == scen_id).delete()
        self.db.query(GraphEdgeModel).filter(GraphEdgeModel.scenario_id == scen_id).delete()
        self.db.query(ValidationFindingModel).filter(ValidationFindingModel.scenario_id == scen_id).delete()

        for node in result.graph.nodes:
            self.db.add(
                GraphNodeModel(
                    id=node.id,
                    scenario_id=scen_id,
                    node_type=node.type.value,
                    label=node.label,
                    data=self._sanitize(node.data),
                )
            )

        for edge in result.graph.edges:
            self.db.add(
                GraphEdgeModel(
                    id=edge.id,
                    scenario_id=scen_id,
                    source=edge.source,
                    target=edge.target,
                    edge_type=edge.edge_type.value,
                    evidence_refs=edge.evidence_refs,
                    metadata_payload=self._sanitize(edge.metadata),
                )
            )

        for f in result.findings:
            self.db.add(
                ValidationFindingModel(
                    id=f.id,
                    scenario_id=scen_id,
                    rule_id=f.rule_id,
                    rule_name=f.rule_name,
                    severity=f.severity.value,
                    affected_node_ids=f.affected_node_ids,
                    affected_edge_ids=f.affected_edge_ids,
                    evidence_refs=f.evidence_refs,
                    explanation=f.explanation,
                    remediation_guidance=f.remediation_guidance,
                )
            )

        # Record analysis run
        run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        self.db.add(
            AnalysisRunModel(
                id=run_id,
                scenario_id=scen_id,
                executed_at=result.timestamp,
                rule_engine_version=result.rule_engine_version,
                dataset_version=result.dataset_version,
                metrics=result.metrics,
                candidate_paths_json=[p.model_dump(mode="json") for p in result.candidate_paths],
                status="completed",
            )
        )
        self.db.commit()

    def record_review(self, finding_id: str, reviewer: str, decision: ReviewStatus, rationale: str) -> ReviewDecisionModel:
        rev_id = f"rev-{finding_id}"
        rec = self.db.query(ReviewDecisionModel).filter(ReviewDecisionModel.id == rev_id).first()
        if not rec:
            rec = ReviewDecisionModel(
                id=rev_id,
                finding_id=finding_id,
                decision=decision.value,
                reviewer=reviewer,
                rationale=rationale,
            )
            self.db.add(rec)
        else:
            rec.decision = decision.value
            rec.reviewer = reviewer
            rec.rationale = rationale
            rec.created_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(rec)
        return rec
