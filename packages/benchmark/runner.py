"""Benchmark Runner and Evaluator for AttackPath Intelligence."""

from __future__ import annotations

import time
from typing import Any, Dict, List
from packages.benchmark.models import (
    BenchmarkGroundTruth,
    BenchmarkScenario,
    BenchmarkScorecard,
    ScenarioScore,
)
from packages.benchmark.suite import create_30_scenarios
from packages.reasoning_engine import AttackPathReasoningEngine
from packages.schemas.models import PathStatus, Severity


class BenchmarkRunner:
    """Executes the benchmark scenario suite and computes defensible evaluation metrics."""

    def __init__(self, engine: Optional[AttackPathReasoningEngine] = None) -> None:
        self.engine = engine or AttackPathReasoningEngine()

    def run_benchmark(self, scenarios: Optional[List[BenchmarkScenario]] = None) -> BenchmarkScorecard:
        suite = scenarios or create_30_scenarios()
        scores: List[ScenarioScore] = []

        total_predicted_edges = 0
        correct_predicted_edges = 0
        total_expected_edges = 0

        total_paths = 0
        valid_paths = 0

        unsupported_claims_asserted = 0
        total_inferred_steps = 0

        injected_contradictions = 0
        detected_contradictions = 0

        total_technique_mappings = 0
        correct_technique_mappings = 0

        findings_with_traceability = 0
        total_findings = 0

        runtimes: List[float] = []
        category_stats: Dict[str, Dict[str, Any]] = {}

        for scen in suite:
            t_start = time.perf_counter()
            result = self.engine.analyze_bundle(scen.bundle)
            runtime_ms = (time.perf_counter() - t_start) * 1000
            runtimes.append(runtime_ms)

            cat = scen.category
            cat_entry = category_stats.setdefault(cat, {"total": 0, "passed": 0})
            cat_entry["total"] += 1

            # 1. Edge Metrics
            predicted_edge_ids = set(e.id for e in result.graph.edges if e.edge_type.value in ("ENABLES", "PRECEDES"))
            expected_edge_ids = set(scen.ground_truth.expected_edge_ids)

            total_predicted_edges += len(predicted_edge_ids)
            total_expected_edges += len(expected_edge_ids)
            intersection_edges = len(predicted_edge_ids.intersection(expected_edge_ids))
            correct_predicted_edges += intersection_edges

            # 2. Path Validity Rate
            error_findings = [f for f in result.findings if f.severity == Severity.ERROR]
            is_graph_valid = len(error_findings) == 0

            for p in result.candidate_paths:
                total_paths += 1
                if is_graph_valid and p.status != PathStatus.CONTRADICTED:
                    valid_paths += 1

            # 3. Unsupported-Claim Rate (UCR)
            # Did the engine ever declare a path or step as SUPPORTED when it lacked evidence?
            for p in result.candidate_paths:
                if p.status == PathStatus.SUPPORTED:
                    if len(p.supporting_observations) < len(p.step_ids):
                        unsupported_claims_asserted += 1
                total_inferred_steps += len(p.step_ids)

            # 4. Contradiction Detection Rate (CDR)
            contra_findings = [f for f in result.findings if f.rule_id == "R501"]
            if scen.ground_truth.has_contradiction:
                injected_contradictions += 1
                if len(contra_findings) > 0 or any(p.status == PathStatus.CONTRADICTED for p in result.candidate_paths):
                    detected_contradictions += 1
                    contradiction_matched = True
                else:
                    contradiction_matched = False
            else:
                contradiction_matched = len(contra_findings) == 0

            # 5. ATT&CK Mapping Precision
            pred_techs = set(m.technique_id for m in result.technique_mappings)
            exp_techs = set(scen.ground_truth.expected_technique_ids)
            total_technique_mappings += len(pred_techs)
            if exp_techs:
                correct_technique_mappings += len(pred_techs.intersection(exp_techs))
            else:
                correct_technique_mappings += len(pred_techs)  # Non-penalty for unconstrained cases

            # 6. Evidence Traceability
            for f in result.findings:
                total_findings += 1
                if f.evidence_refs or f.affected_node_ids:
                    findings_with_traceability += 1

            # Status match check
            pred_status = result.candidate_paths[0].status if result.candidate_paths else PathStatus.UNSUBSTANTIATED
            status_matched = (pred_status == scen.ground_truth.expected_path_status)

            detected_rule_ids = [f.rule_id for f in result.findings]
            expected_rules = scen.ground_truth.expected_finding_rule_ids
            findings_matched = all(r in detected_rule_ids for r in expected_rules)

            scenario_passed = status_matched and findings_matched and contradiction_matched
            if scenario_passed:
                cat_entry["passed"] += 1

            scores.append(
                ScenarioScore(
                    scenario_id=scen.id,
                    category=scen.category,
                    status_matched=status_matched,
                    predicted_status=pred_status,
                    expected_status=scen.ground_truth.expected_path_status,
                    findings_matched=findings_matched,
                    detected_rules=detected_rule_ids,
                    expected_rules=expected_rules,
                    contradiction_matched=contradiction_matched,
                    runtime_ms=round(runtime_ms, 2),
                    notes=scen.ground_truth.rationale,
                )
            )

        edge_precision = (correct_predicted_edges / total_predicted_edges) if total_predicted_edges > 0 else 1.0
        edge_recall = (correct_predicted_edges / total_expected_edges) if total_expected_edges > 0 else 1.0
        path_validity_rate = (valid_paths / total_paths) if total_paths > 0 else 1.0
        unsupported_claim_rate = (unsupported_claims_asserted / max(1, total_inferred_steps))
        cdr = (detected_contradictions / injected_contradictions) if injected_contradictions > 0 else 1.0
        attack_prec = (correct_technique_mappings / max(1, total_technique_mappings))
        traceability = (findings_with_traceability / max(1, total_findings))
        mean_runtime = sum(runtimes) / len(runtimes) if runtimes else 0.0
        passed_count = sum(1 for s in scores if s.status_matched and s.findings_matched and s.contradiction_matched)

        return BenchmarkScorecard(
            version="1.0.0",
            total_scenarios=len(suite),
            passed_scenarios=passed_count,
            edge_precision=round(edge_precision, 4),
            edge_recall=round(edge_recall, 4),
            path_validity_rate=round(path_validity_rate, 4),
            unsupported_claim_rate=round(unsupported_claim_rate, 4),
            contradiction_detection_rate=round(cdr, 4),
            attack_mapping_precision=round(attack_prec, 4),
            evidence_traceability_rate=round(traceability, 4),
            mean_runtime_ms=round(mean_runtime, 2),
            category_breakdown=category_stats,
            scenario_scores=scores,
        )
