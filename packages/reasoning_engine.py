"""High-level AttackPath Reasoning Engine orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from packages.attack_mapper.kb import AttackKnowledgeBase
from packages.attack_mapper.mapper import TechniqueMapper
from packages.graph_engine.engine import AttackGraphEngine
from packages.schemas.models import (
    AnalysisResult,
    CandidatePath,
    EdgeType,
    Finding,
    NodeType,
    PathStatus,
    ScenarioBundle,
    Severity,
    TechniqueMappingRecord,
)
from packages.validators.runner import RuleEngineRunner


class AttackPathReasoningEngine:
    """End-to-end reasoning engine converting security observations into defensible attack-path analyses."""

    def __init__(
        self,
        kb: Optional[AttackKnowledgeBase] = None,
        rule_runner: Optional[RuleEngineRunner] = None,
    ) -> None:
        self.kb = kb or AttackKnowledgeBase()
        self.mapper = TechniqueMapper(kb=self.kb)
        self.rule_runner = rule_runner or RuleEngineRunner()

    def analyze_bundle(self, bundle: ScenarioBundle) -> AnalysisResult:
        engine = AttackGraphEngine()

        # 1. Register Assets
        for asset in bundle.assets:
            engine.add_asset(asset)

        # 2. Register Observations
        for obs in bundle.observations:
            engine.add_observation(obs)

        # 3. Register Hypothesized Attack Steps
        for step in bundle.hypotheses:
            engine.add_attack_step(step)

        # 4. Register Security Controls
        for ctrl in bundle.controls:
            engine.add_security_control(ctrl)

        # 5. Add Explicit Edges
        for edge in bundle.explicit_edges:
            engine.add_edge(
                source=edge.source,
                target=edge.target,
                edge_type=edge.edge_type,
                edge_id=edge.id,
                evidence_refs=edge.evidence_refs,
                metadata=edge.metadata,
            )

        # 6. Execute MITRE ATT&CK Mapping
        all_mappings: List[TechniqueMappingRecord] = []
        for obs in bundle.observations:
            maps = self.mapper.map_observation(obs)
            all_mappings.extend(maps)
            for m in maps:
                tech = self.kb.get_by_id(m.technique_id)
                if tech:
                    engine.add_technique(tech)
                    engine.add_edge(
                        source=obs.id,
                        target=tech.technique_id,
                        edge_type=EdgeType.MAPPED_TO,
                        evidence_refs=[obs.id],
                        metadata={"rationale": m.rationale, "status": m.status.value},
                    )

        for step in bundle.hypotheses:
            maps = self.mapper.map_attack_step(step)
            all_mappings.extend(maps)
            for m in maps:
                tech = self.kb.get_by_id(m.technique_id)
                if tech:
                    engine.add_technique(tech)
                    engine.add_edge(
                        source=step.id,
                        target=tech.technique_id,
                        edge_type=EdgeType.MAPPED_TO,
                        evidence_refs=[],
                        metadata={"rationale": m.rationale, "status": m.status.value},
                    )

        # 7. Execute Deterministic Rule Engine
        findings: List[Finding] = self.rule_runner.run(engine)

        # Add Findings into graph as nodes
        for f in findings:
            engine.add_finding(f)

        # 8. Bounded Candidate Paths & Uncertainty Assessment
        candidate_paths = engine.generate_alternative_paths()

        # 9. Compute Summary Metrics
        total_steps = len(bundle.hypotheses)
        observed_steps = sum(
            1 for s in bundle.hypotheses if engine.get_supporting_evidence(s.id)
        )
        evidence_coverage = (observed_steps / total_steps) if total_steps > 0 else 1.0

        error_count = sum(1 for f in findings if f.severity == Severity.ERROR)
        warning_count = sum(1 for f in findings if f.severity == Severity.WARNING)
        info_count = sum(1 for f in findings if f.severity == Severity.INFO)

        metrics = {
            "total_nodes": len(engine.get_all_nodes()),
            "total_edges": len(engine.get_all_edges()),
            "total_observations": len(bundle.observations),
            "total_attack_steps": total_steps,
            "evidence_coverage_ratio": round(evidence_coverage, 4),
            "findings_count": {
                "total": len(findings),
                "error": error_count,
                "warning": warning_count,
                "info": info_count,
            },
            "candidate_paths_count": len(candidate_paths),
            "path_statuses": {
                status.value: sum(1 for p in candidate_paths if p.status == status)
                for status in PathStatus
            },
        }

        return AnalysisResult(
            scenario_id=bundle.scenario.id,
            timestamp=datetime.now(timezone.utc),
            rule_engine_version="1.0.0",
            dataset_version="ATT&CK v15.1",
            graph=engine.export(),
            findings=findings,
            candidate_paths=candidate_paths,
            technique_mappings=all_mappings,
            metrics=metrics,
        )
