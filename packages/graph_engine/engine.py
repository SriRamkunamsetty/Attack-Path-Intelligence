"""NetworkX-based Attack Graph Engine for AttackPath Intelligence."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from packages.schemas.models import (
    Asset,
    AttackGraphExport,
    AttackStep,
    CandidatePath,
    EdgeType,
    Finding,
    GraphEdge,
    GraphNode,
    NodeType,
    Observation,
    PathStatus,
    SecurityControl,
    Technique,
)


class AttackGraphEngine:
    """Core directed attack graph engine powered by NetworkX."""

    def __init__(self) -> None:
        # MultiDiGraph allows multiple directed edges with different types between two nodes
        self.graph = nx.MultiDiGraph()
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[str, GraphEdge] = {}

    # -------------------------------------------------------------------------
    # Node Management
    # -------------------------------------------------------------------------

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add or update a node in the graph."""
        payload = data or {}
        self._nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "data": payload,
        }
        self.graph.add_node(
            node_id,
            node_type=node_type.value,
            label=label,
            **payload,
        )

    def add_asset(self, asset: Asset) -> None:
        self.add_node(
            node_id=asset.id,
            node_type=NodeType.ASSET,
            label=asset.name,
            data=asset.model_dump(),
        )

    def add_observation(self, obs: Observation) -> None:
        self.add_node(
            node_id=obs.id,
            node_type=NodeType.OBSERVATION,
            label=obs.description[:50],
            data=obs.model_dump(),
        )

    def add_attack_step(self, step: AttackStep) -> None:
        self.add_node(
            node_id=step.id,
            node_type=NodeType.ATTACK_STEP,
            label=step.title,
            data=step.model_dump(),
        )

    def add_technique(self, tech: Technique) -> None:
        self.add_node(
            node_id=tech.technique_id,
            node_type=NodeType.TECHNIQUE,
            label=f"{tech.technique_id}: {tech.name}",
            data=tech.model_dump(),
        )

    def add_security_control(self, ctrl: SecurityControl) -> None:
        self.add_node(
            node_id=ctrl.id,
            node_type=NodeType.SECURITY_CONTROL,
            label=ctrl.name,
            data=ctrl.model_dump(),
        )

    def add_finding(self, finding: Finding) -> None:
        self.add_node(
            node_id=finding.id,
            node_type=NodeType.FINDING,
            label=f"[{finding.severity}] {finding.rule_name}",
            data=finding.model_dump(),
        )

    # -------------------------------------------------------------------------
    # Edge Management
    # -------------------------------------------------------------------------

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        edge_id: Optional[str] = None,
        evidence_refs: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GraphEdge:
        """Add a typed directed edge between source and target nodes."""
        evidence = evidence_refs or []
        meta = metadata or {}
        eid = edge_id or f"{source}->{edge_type.value}->{target}"

        edge = GraphEdge(
            id=eid,
            source=source,
            target=target,
            edge_type=edge_type,
            evidence_refs=evidence,
            metadata=meta,
        )
        self._edges[eid] = edge

        self.graph.add_edge(
            source,
            target,
            key=eid,
            edge_id=eid,
            edge_type=edge_type.value,
            evidence_refs=evidence,
            **meta,
        )
        return edge

    # -------------------------------------------------------------------------
    # Query & Traversal Helpers
    # -------------------------------------------------------------------------

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self._nodes.get(node_id)

    def get_all_nodes(self) -> List[GraphNode]:
        return [
            GraphNode(
                id=n["id"],
                type=n["type"],
                label=n["label"],
                data=n["data"],
            )
            for n in self._nodes.values()
        ]

    def get_all_edges(self) -> List[GraphEdge]:
        return list(self._edges.values())

    def get_edges_between(self, u: str, v: str) -> List[GraphEdge]:
        edges = []
        if self.graph.has_edge(u, v):
            edge_dict = self.graph.get_edge_data(u, v)
            for key in edge_dict:
                if key in self._edges:
                    edges.append(self._edges[key])
        return edges

    def get_supporting_evidence(self, step_id: str) -> List[str]:
        """Return IDs of observations that directly substantiate this attack step."""
        evidence_ids: List[str] = []
        # Check incoming OBSERVED_AS edges (Step -> Observation or Observation -> Step)
        # By convention: AttackStep -OBSERVED_AS-> Observation
        for _, target, data in self.graph.out_edges(step_id, data=True):
            if data.get("edge_type") == EdgeType.OBSERVED_AS.value:
                evidence_ids.append(target)
        # Also check reverse in case graph was wired Observation -> OBSERVED_AS -> AttackStep
        for source, _, data in self.graph.in_edges(step_id, data=True):
            if data.get("edge_type") == EdgeType.OBSERVED_AS.value:
                evidence_ids.append(source)
        return list(set(evidence_ids))

    def get_contradictions(self, target_id: str) -> List[str]:
        """Return IDs of observations or nodes that contradict this target."""
        contradictions: List[str] = []
        for source, _, data in self.graph.in_edges(target_id, data=True):
            if data.get("edge_type") == EdgeType.CONTRADICTS.value:
                contradictions.append(source)
        return list(set(contradictions))

    def get_mitigating_controls(self, step_id: str) -> List[str]:
        """Return IDs of security controls mitigating this attack step."""
        controls: List[str] = []
        for _, target, data in self.graph.out_edges(step_id, data=True):
            if data.get("edge_type") == EdgeType.MITIGATED_BY.value:
                controls.append(target)
        return list(set(controls))

    # -------------------------------------------------------------------------
    # Candidate Attack Path Analysis
    # -------------------------------------------------------------------------

    def find_candidate_paths(
        self,
        start_step_id: str,
        target_step_id: str,
        max_depth: int = 10,
    ) -> List[CandidatePath]:
        """Traverse causal (ENABLES) and temporal (PRECEDES) steps from start to target."""
        if not self.has_node(start_step_id) or not self.has_node(target_step_id):
            return []

        # Subgraph considering only AttackStep nodes and ENABLES / PRECEDES edges
        step_subgraph = nx.DiGraph()
        for u, v, data in self.graph.edges(data=True):
            etype = data.get("edge_type")
            if etype in (EdgeType.ENABLES.value, EdgeType.PRECEDES.value):
                # Only connect AttackSteps or Observations
                u_type = self._nodes.get(u, {}).get("type")
                v_type = self._nodes.get(v, {}).get("type")
                if u_type in (NodeType.ATTACK_STEP, NodeType.OBSERVATION) and v_type in (NodeType.ATTACK_STEP, NodeType.OBSERVATION):
                    step_subgraph.add_edge(u, v, edge_type=etype, edge_id=data.get("edge_id"))

        if not step_subgraph.has_node(start_step_id) or not step_subgraph.has_node(target_step_id):
            return []

        candidate_paths: List[CandidatePath] = []
        try:
            raw_paths = list(
                nx.all_simple_paths(
                    step_subgraph,
                    source=start_step_id,
                    target=target_step_id,
                    cutoff=max_depth,
                )
            )
        except Exception:
            raw_paths = []

        for idx, path_nodes in enumerate(raw_paths):
            path_id = f"path-{idx + 1}"
            path_edge_ids: List[str] = []
            for i in range(len(path_nodes) - 1):
                u = path_nodes[i]
                v = path_nodes[i + 1]
                edata = step_subgraph.get_edge_data(u, v)
                if edata and "edge_id" in edata:
                    path_edge_ids.append(edata["edge_id"])

            # Evaluate evidence, contradictions, and status for this path
            status, rationale, supp_obs, assumptions, missing, conf, disc = self._evaluate_path_validity(path_nodes)

            candidate_paths.append(
                CandidatePath(
                    path_id=path_id,
                    name=f"Hypothesis {idx + 1}: {path_nodes[0]} -> {path_nodes[-1]}",
                    step_ids=path_nodes,
                    edge_ids=path_edge_ids,
                    status=status,
                    confidence_rationale=rationale,
                    supporting_observations=supp_obs,
                    required_assumptions=assumptions,
                    missing_evidence=missing,
                    conflicting_evidence=conf,
                    discriminator_evidence=disc,
                    potential_impact="Unauthorized access, credential compromise, or policy violation",
                )
            )

        return candidate_paths

    def _evaluate_path_validity(
        self, path_nodes: List[str]
    ) -> Tuple[PathStatus, str, List[str], List[str], List[str], List[str], List[str]]:
        """Evaluate evidence coverage, assumptions, and contradictions for a candidate path."""
        supporting_obs: Set[str] = set()
        required_assumptions: List[str] = []
        missing_evidence: List[str] = []
        conflicting_evidence: List[str] = []
        discriminator_evidence: List[str] = []

        supported_steps_count = 0
        total_steps = len(path_nodes)

        for node_id in path_nodes:
            node_meta = self._nodes.get(node_id, {})
            ntype = node_meta.get("type")

            # Check if this node is an observation directly
            if ntype == NodeType.OBSERVATION:
                supporting_obs.add(node_id)
                supported_steps_count += 1
            else:
                # AttackStep: check supporting evidence
                ev = self.get_supporting_evidence(node_id)
                if ev:
                    supporting_obs.update(ev)
                    supported_steps_count += 1
                else:
                    required_assumptions.append(f"Assumption: Step '{node_meta.get('label')}' occurred without log trace")
                    missing_evidence.append(f"Missing telemetry proving '{node_meta.get('label')}'")

            # Check contradictions
            contra = self.get_contradictions(node_id)
            if contra:
                conflicting_evidence.extend(contra)

        # Discriminator telemetry recommendations
        discriminator_evidence.append("Session cookie correlation and IP geo-velocity telemetry")
        discriminator_evidence.append("Host endpoint process tree and parent PID verification")
        discriminator_evidence.append("Privileged identity management (PIM) approval logs")

        # Determine path status
        if conflicting_evidence:
            status = PathStatus.CONTRADICTED
            rationale = (
                f"Path is CONTRADICTED by {len(conflicting_evidence)} verified piece(s) of contradictory evidence: "
                f"{', '.join(conflicting_evidence)}."
            )
        elif supported_steps_count == total_steps:
            status = PathStatus.SUPPORTED
            rationale = (
                f"All {total_steps} steps along this trajectory are substantiated by direct security observations."
            )
        elif supported_steps_count > 0:
            status = PathStatus.PARTIALLY_SUPPORTED
            rationale = (
                f"{supported_steps_count} of {total_steps} steps are supported by observations, "
                f"while {len(required_assumptions)} rely on unverified assumptions."
            )
        else:
            status = PathStatus.UNSUBSTANTIATED
            rationale = "Critical attack steps completely lack supporting observations."

        return (
            status,
            rationale,
            list(supporting_obs),
            required_assumptions,
            missing_evidence,
            conflicting_evidence,
            discriminator_evidence,
        )

    # -------------------------------------------------------------------------
    # Alternative Explanations Generator
    # -------------------------------------------------------------------------

    def generate_alternative_paths(
        self,
        entry_asset_id: Optional[str] = None,
        target_asset_id: Optional[str] = None,
    ) -> List[CandidatePath]:
        """Identify candidate attack paths across all entry points to target objectives."""
        attack_steps = [
            nid for nid, nmeta in self._nodes.items()
            if nmeta.get("type") == NodeType.ATTACK_STEP
        ]
        if not attack_steps:
            return []

        # Find entry steps (in-degree == 0 among attack steps) and terminal steps (out-degree == 0)
        entry_steps = []
        target_steps = []

        for step_id in attack_steps:
            # Check predecessors
            preds = [
                u for u, _, data in self.graph.in_edges(step_id, data=True)
                if data.get("edge_type") in (EdgeType.ENABLES.value, EdgeType.PRECEDES.value)
            ]
            succs = [
                v for _, v, data in self.graph.out_edges(step_id, data=True)
                if data.get("edge_type") in (EdgeType.ENABLES.value, EdgeType.PRECEDES.value)
            ]
            if not preds:
                entry_steps.append(step_id)
            if not succs:
                target_steps.append(step_id)

        # Fallback if cyclic or connected
        if not entry_steps:
            entry_steps = attack_steps[:1]
        if not target_steps:
            target_steps = attack_steps[-1:]

        all_paths: List[CandidatePath] = []
        for entry in entry_steps:
            for target in target_steps:
                if entry != target:
                    paths = self.find_candidate_paths(entry, target)
                    all_paths.extend(paths)

        return all_paths

    # -------------------------------------------------------------------------
    # Export
    # -------------------------------------------------------------------------

    def export(self) -> AttackGraphExport:
        """Export graph to schema model compatible with frontend React Flow."""
        return AttackGraphExport(
            nodes=self.get_all_nodes(),
            edges=self.get_all_edges(),
        )
