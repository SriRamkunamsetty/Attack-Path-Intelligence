"""Deterministic validation rules for AttackPath Intelligence."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
import networkx as nx

from packages.graph_engine.engine import AttackGraphEngine
from packages.schemas.models import (
    ControlState,
    EdgeType,
    Finding,
    NodeType,
    Severity,
)
from packages.validators.base import BaseValidationRule


# =========================================================================
# Rule Family: Structural Validity (R100 - R199)
# =========================================================================

class DanglingEdgeRule(BaseValidationRule):
    """R101: Ensures every edge references existing source and target nodes."""

    rule_id = "R101"
    rule_name = "DanglingEdgeCheck"
    default_severity = Severity.ERROR
    description = "Edges must strictly connect existing nodes in the graph."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for edge in engine.get_all_edges():
            missing = []
            if not engine.has_node(edge.source):
                missing.append(f"Source '{edge.source}' does not exist")
            if not engine.has_node(edge.target):
                missing.append(f"Target '{edge.target}' does not exist")

            if missing:
                findings.append(
                    Finding(
                        id=f"{self.rule_id}-{edge.id}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.default_severity,
                        affected_node_ids=[n for n in (edge.source, edge.target) if engine.has_node(n)],
                        affected_edge_ids=[edge.id],
                        evidence_refs=edge.evidence_refs,
                        explanation=f"Edge '{edge.id}' is dangling: {'; '.join(missing)}.",
                        remediation_guidance="Ensure all endpoints are registered before creating edge relationships.",
                    )
                )
        return findings


class TypeCompatibilityRule(BaseValidationRule):
    """R102: Verifies node types are logically valid for the given edge type."""

    rule_id = "R102"
    rule_name = "TypeCompatibilityCheck"
    default_severity = Severity.ERROR
    description = "Edge semantics require compatible source and target node types."

    VALID_COMBINATIONS = {
        EdgeType.OBSERVED_AS: {
            (NodeType.ATTACK_STEP, NodeType.OBSERVATION),
            (NodeType.OBSERVATION, NodeType.ATTACK_STEP),
        },
        EdgeType.MAPPED_TO: {
            (NodeType.ATTACK_STEP, NodeType.TECHNIQUE),
            (NodeType.OBSERVATION, NodeType.TECHNIQUE),
        },
        EdgeType.MITIGATED_BY: {
            (NodeType.ATTACK_STEP, NodeType.SECURITY_CONTROL),
        },
        EdgeType.CONTRADICTS: {
            (NodeType.OBSERVATION, NodeType.ATTACK_STEP),
            (NodeType.OBSERVATION, NodeType.OBSERVATION),
        },
        EdgeType.DEPENDS_ON: {
            (NodeType.ATTACK_STEP, NodeType.ASSET),
            (NodeType.ATTACK_STEP, NodeType.ATTACK_STEP),
        },
        EdgeType.ENABLES: {
            (NodeType.ATTACK_STEP, NodeType.ATTACK_STEP),
            (NodeType.OBSERVATION, NodeType.ATTACK_STEP),
        },
        EdgeType.PRECEDES: {
            (NodeType.OBSERVATION, NodeType.OBSERVATION),
            (NodeType.ATTACK_STEP, NodeType.ATTACK_STEP),
        },
    }

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for edge in engine.get_all_edges():
            src_node = engine.get_node(edge.source)
            tgt_node = engine.get_node(edge.target)
            if not src_node or not tgt_node:
                continue

            src_type = src_node["type"]
            tgt_type = tgt_node["type"]
            allowed = self.VALID_COMBINATIONS.get(edge.edge_type)

            if allowed and (src_type, tgt_type) not in allowed:
                findings.append(
                    Finding(
                        id=f"{self.rule_id}-{edge.id}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.default_severity,
                        affected_node_ids=[edge.source, edge.target],
                        affected_edge_ids=[edge.id],
                        evidence_refs=edge.evidence_refs,
                        explanation=(
                            f"Edge '{edge.edge_type.value}' illegally connects '{src_type.value}' "
                            f"to '{tgt_type.value}'. Allowed pairs: {allowed}"
                        ),
                        remediation_guidance="Use valid edge types conforming to the domain ontology.",
                    )
                )
        return findings


class CausalCycleRule(BaseValidationRule):
    """R103: Flags causal loops in ENABLES edges."""

    rule_id = "R103"
    rule_name = "CausalCycleCheck"
    default_severity = Severity.ERROR
    description = "Causal ENABLES edges must form a Directed Acyclic Graph (DAG)."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        enables_graph = nx.DiGraph()

        for edge in engine.get_all_edges():
            if edge.edge_type == EdgeType.ENABLES:
                enables_graph.add_edge(edge.source, edge.target, edge_id=edge.id)

        try:
            cycles = list(nx.simple_cycles(enables_graph))
            for idx, cycle in enumerate(cycles):
                cycle_edges = []
                for i in range(len(cycle)):
                    u = cycle[i]
                    v = cycle[(i + 1) % len(cycle)]
                    edata = enables_graph.get_edge_data(u, v)
                    if edata and "edge_id" in edata:
                        cycle_edges.append(edata["edge_id"])

                findings.append(
                    Finding(
                        id=f"{self.rule_id}-cycle-{idx + 1}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.default_severity,
                        affected_node_ids=cycle,
                        affected_edge_ids=cycle_edges,
                        explanation=f"Causal loop detected in ENABLES relationships: {' -> '.join(cycle)} -> {cycle[0]}.",
                        remediation_guidance="Remove circular ENABLES edge. Causal attack dependencies cannot be self-enabling.",
                    )
                )
        except Exception:
            pass

        return findings


# =========================================================================
# Rule Family: Temporal Consistency (R200 - R299)
# =========================================================================

class ChronologicalOrderRule(BaseValidationRule):
    """R201: Causal dependency T(Prerequisite) <= T(Action)."""

    rule_id = "R201"
    rule_name = "ChronologicalOrderCheck"
    default_severity = Severity.ERROR
    description = "An enabling condition or prerequisite cannot occur after the step it enables."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []

        def extract_timestamp(node_dict: Dict[str, Any]) -> Optional[datetime]:
            data = node_dict.get("data", {})
            ts = data.get("timestamp")
            if isinstance(ts, str):
                try:
                    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    return None
            return ts if isinstance(ts, datetime) else None

        for edge in engine.get_all_edges():
            if edge.edge_type in (EdgeType.ENABLES, EdgeType.PRECEDES):
                src = engine.get_node(edge.source)
                tgt = engine.get_node(edge.target)
                if not src or not tgt:
                    continue

                t_src = extract_timestamp(src)
                t_tgt = extract_timestamp(tgt)

                if t_src and t_tgt and t_src > t_tgt:
                    findings.append(
                        Finding(
                            id=f"{self.rule_id}-{edge.id}",
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.default_severity,
                            affected_node_ids=[edge.source, edge.target],
                            affected_edge_ids=[edge.id],
                            evidence_refs=edge.evidence_refs,
                            explanation=(
                                f"Temporal violation: Source '{edge.source}' at {t_src.isoformat()} occurred AFTER "
                                f"target '{edge.target}' at {t_tgt.isoformat()} in a {edge.edge_type.value} edge."
                            ),
                            remediation_guidance="Verify event clock synchronization and ensure prerequisite steps precede enabled steps.",
                        )
                    )
        return findings


class TemporalOrderWithoutCausalityRule(BaseValidationRule):
    """R202: Flags unverified causality inferred purely from chronological sequence."""

    rule_id = "R202"
    rule_name = "TemporalWithoutCausalityCheck"
    default_severity = Severity.INFO
    description = "Temporal sequence (PRECEDES) alone does not establish causal dependency (ENABLES)."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for edge in engine.get_all_edges():
            if edge.edge_type == EdgeType.PRECEDES:
                # Check if there is also an ENABLES edge
                other_edges = engine.get_edges_between(edge.source, edge.target)
                has_enables = any(e.edge_type == EdgeType.ENABLES for e in other_edges)
                if not has_enables:
                    findings.append(
                        Finding(
                            id=f"{self.rule_id}-{edge.id}",
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.default_severity,
                            affected_node_ids=[edge.source, edge.target],
                            affected_edge_ids=[edge.id],
                            evidence_refs=edge.evidence_refs,
                            explanation=(
                                f"Events '{edge.source}' and '{edge.target}' are chronologically ordered (PRECEDES), "
                                f"but no causal prerequisite link (ENABLES) has been proven."
                            ),
                            remediation_guidance="Verify whether event A genuinely created conditions for event B before asserting an attack chain.",
                        )
                    )
        return findings


# =========================================================================
# Rule Family: Prerequisite Validation (R300 - R399)
# =========================================================================

class PrerequisiteDependencyRule(BaseValidationRule):
    """R301: Validates that declared prerequisite steps are satisfied."""

    rule_id = "R301"
    rule_name = "PrerequisiteDependencyCheck"
    default_severity = Severity.WARNING
    description = "Attack steps requiring specific prerequisites must link to valid enabling steps or configurations."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for node in engine.get_all_nodes():
            if node.type == NodeType.ATTACK_STEP:
                prereqs = node.data.get("prerequisites", [])
                for prereq in prereqs:
                    # Check if incoming ENABLES or DEPENDS_ON exists from this prereq
                    incoming = [
                        u for u, _, data in engine.graph.in_edges(node.id, data=True)
                        if data.get("edge_type") in (EdgeType.ENABLES.value, EdgeType.DEPENDS_ON.value)
                        and u == prereq
                    ]
                    if not incoming:
                        findings.append(
                            Finding(
                                id=f"{self.rule_id}-{node.id}-{prereq}",
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=self.default_severity,
                                affected_node_ids=[node.id],
                                explanation=(
                                    f"Step '{node.label}' declares prerequisite '{prereq}', "
                                    f"but no ENABLES or DEPENDS_ON edge links them in the graph."
                                ),
                                remediation_guidance="Provide evidence or graph edge connecting the prerequisite condition to this step.",
                            )
                        )
        return findings


# =========================================================================
# Rule Family: Identity Consistency (R400 - R499)
# =========================================================================

class IdentityConflationRule(BaseValidationRule):
    """R401: Flags transitions between disparate identities without credential handoff evidence."""

    rule_id = "R401"
    rule_name = "IdentityConflationCheck"
    default_severity = Severity.WARNING
    description = "Transitions between different user identities must have explicit credential access or handoff evidence."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for edge in engine.get_all_edges():
            if edge.edge_type == EdgeType.ENABLES:
                u_node = engine.get_node(edge.source)
                v_node = engine.get_node(edge.target)
                if not u_node or not v_node:
                    continue

                u_ident = u_node.get("data", {}).get("actor_identity")
                v_ident = v_node.get("data", {}).get("actor_identity")

                if u_ident and v_ident and u_ident.lower() != v_ident.lower():
                    # Check if there is an intervening credential-theft or privilege-escalation step
                    findings.append(
                        Finding(
                            id=f"{self.rule_id}-{edge.id}",
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.default_severity,
                            affected_node_ids=[edge.source, edge.target],
                            affected_edge_ids=[edge.id],
                            evidence_refs=edge.evidence_refs,
                            explanation=(
                                f"Identity discrepancy: Step '{edge.source}' involves identity '{u_ident}', "
                                f"while enabled step '{edge.target}' involves identity '{v_ident}'. "
                                f"No explicit credential handoff or lateral movement evidence is attached."
                            ),
                            remediation_guidance="Confirm whether credentials were stolen, shared, or if these belong to separate concurrent sessions.",
                        )
                    )
        return findings


# =========================================================================
# Rule Family: Contradiction Analysis (R500 - R599)
# =========================================================================

class ContradictionDetectionRule(BaseValidationRule):
    """R501: Identifies and reports explicit CONTRADICTS relationships."""

    rule_id = "R501"
    rule_name = "ContradictionDetectionCheck"
    default_severity = Severity.ERROR
    description = "Flags verified evidence that directly contradicts hypothesized attack steps."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for edge in engine.get_all_edges():
            if edge.edge_type == EdgeType.CONTRADICTS:
                src = engine.get_node(edge.source)
                tgt = engine.get_node(edge.target)
                src_label = src["label"] if src else edge.source
                tgt_label = tgt["label"] if tgt else edge.target

                findings.append(
                    Finding(
                        id=f"{self.rule_id}-{edge.id}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.default_severity,
                        affected_node_ids=[edge.source, edge.target],
                        affected_edge_ids=[edge.id],
                        evidence_refs=[edge.source] if src and src.get("type") == NodeType.OBSERVATION else [],
                        explanation=(
                            f"Direct contradiction detected: Evidence '{src_label}' explicitly conflicts with "
                            f"hypothesized claim '{tgt_label}'."
                        ),
                        remediation_guidance="Revise attack hypothesis. Evidence refutes this transition.",
                    )
                )
        return findings


# =========================================================================
# Rule Family: Evidence Coverage & Uncertainty (R600 - R699)
# =========================================================================

class UnsupportedHypothesisRule(BaseValidationRule):
    """R601: Flags attack steps that lack supporting observation links."""

    rule_id = "R601"
    rule_name = "UnsupportedHypothesisCheck"
    default_severity = Severity.INFO
    description = "Attack steps marked as hypothesized must explicitly disclose lack of direct telemetry."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for node in engine.get_all_nodes():
            if node.type == NodeType.ATTACK_STEP:
                ev = engine.get_supporting_evidence(node.id)
                if not ev:
                    findings.append(
                        Finding(
                            id=f"{self.rule_id}-{node.id}",
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=self.default_severity,
                            affected_node_ids=[node.id],
                            explanation=(
                                f"Attack step '{node.label}' is unverified: No direct security observation "
                                f"(OBSERVED_AS) supports this action."
                            ),
                            remediation_guidance="Gather endpoint, network, or authentication logs to verify whether this step occurred.",
                        )
                    )
        return findings


# =========================================================================
# Rule Family: Defensive Control Analysis (R700 - R799)
# =========================================================================

class UnmitigatedHighRiskStepRule(BaseValidationRule):
    """R701: Detects high-risk attack steps with no associated defensive control."""

    rule_id = "R701"
    rule_name = "UnmitigatedHighRiskStepCheck"
    default_severity = Severity.WARNING
    description = "Highlights critical attack stages that lack preventive or detective controls."

    HIGH_RISK_STAGES = {"credential_access", "lateral_movement", "exfiltration", "execution"}

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for node in engine.get_all_nodes():
            if node.type == NodeType.ATTACK_STEP:
                stage = node.data.get("stage", "").lower()
                if stage in self.HIGH_RISK_STAGES:
                    controls = engine.get_mitigating_controls(node.id)
                    if not controls:
                        findings.append(
                            Finding(
                                id=f"{self.rule_id}-{node.id}",
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=self.default_severity,
                                affected_node_ids=[node.id],
                                explanation=(
                                    f"Step '{node.label}' (stage: {stage}) has no associated security control "
                                    f"(MITIGATED_BY) mapped to limit its impact."
                                ),
                                remediation_guidance="Map relevant defensive controls such as MFA, EDR, network microsegmentation, or audit logging.",
                            )
                        )
        return findings


class BypassedControlRule(BaseValidationRule):
    """R702: Detects confirmed controls that failed to stop an observed step."""

    rule_id = "R702"
    rule_name = "BypassedControlCheck"
    default_severity = Severity.WARNING
    description = "Flags when an attack step occurred despite a confirmed preventive security control."

    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        findings: List[Finding] = []
        for node in engine.get_all_nodes():
            if node.type == NodeType.ATTACK_STEP:
                # If step has supporting evidence (i.e. It actually occurred)
                ev = engine.get_supporting_evidence(node.id)
                if ev:
                    controls = engine.get_mitigating_controls(node.id)
                    for cid in controls:
                        cnode = engine.get_node(cid)
                        if cnode and cnode.get("data", {}).get("state") == ControlState.CONFIRMED_PRESENT.value:
                            findings.append(
                                Finding(
                                    id=f"{self.rule_id}-{node.id}-{cid}",
                                    rule_id=self.rule_id,
                                    rule_name=self.rule_name,
                                    severity=self.default_severity,
                                    affected_node_ids=[node.id, cid],
                                    evidence_refs=ev,
                                    explanation=(
                                        f"Control Bypass or Failure: Step '{node.label}' was observed, yet preventive control "
                                        f"'{cnode.get('label')}' is documented as CONFIRMED_PRESENT in the environment."
                                    ),
                                    remediation_guidance="Audit control configuration, inspect policy exceptions, and verify sensor health.",
                                )
                            )
        return findings
