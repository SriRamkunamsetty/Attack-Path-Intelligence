"""Unit tests for AttackGraphEngine and RuleEngineRunner."""

from datetime import datetime, timezone
import pytest

from packages.graph_engine.engine import AttackGraphEngine
from packages.schemas.models import (
    Asset,
    AssetType,
    AttackStep,
    ControlState,
    EdgeType,
    NodeType,
    Observation,
    PathStatus,
    SecurityControl,
    Severity,
)
from packages.validators.runner import RuleEngineRunner


def test_graph_add_and_query():
    engine = AttackGraphEngine()
    asset = Asset(id="host-1", name="DC-01", asset_type=AssetType.HOST)
    engine.add_asset(asset)

    assert engine.has_node("host-1")
    node = engine.get_node("host-1")
    assert node is not None
    assert node["label"] == "DC-01"
    assert node["type"] == NodeType.ASSET


def test_dangling_edge_detected():
    engine = AttackGraphEngine()
    engine.add_node("step-1", NodeType.ATTACK_STEP, "Phishing")
    # Add edge to non-existent target
    engine.add_edge("step-1", "non-existent-target", EdgeType.ENABLES)

    runner = RuleEngineRunner()
    findings = runner.run(engine)

    dangling = [f for f in findings if f.rule_id == "R101"]
    assert len(dangling) == 1
    assert dangling[0].severity == Severity.ERROR
    assert "non-existent-target" in dangling[0].explanation


def test_causal_cycle_detected():
    engine = AttackGraphEngine()
    engine.add_node("step-1", NodeType.ATTACK_STEP, "Step 1")
    engine.add_node("step-2", NodeType.ATTACK_STEP, "Step 2")
    engine.add_edge("step-1", "step-2", EdgeType.ENABLES)
    engine.add_edge("step-2", "step-1", EdgeType.ENABLES)

    runner = RuleEngineRunner()
    findings = runner.run(engine)

    cycle_findings = [f for f in findings if f.rule_id == "R103"]
    assert len(cycle_findings) >= 1
    assert cycle_findings[0].severity == Severity.ERROR


def test_temporal_order_violation():
    engine = AttackGraphEngine()
    t1 = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 18, 11, 0, 0, tzinfo=timezone.utc)

    step1 = AttackStep(id="step-1", title="Initial Login", timestamp=t1)
    step2 = AttackStep(id="step-2", title="Preceding Recon", timestamp=t2)

    engine.add_attack_step(step1)
    engine.add_attack_step(step2)

    # step1 (12:00) claimed to ENABLES step2 (11:00) -> Impossible!
    engine.add_edge("step-1", "step-2", EdgeType.ENABLES)

    runner = RuleEngineRunner()
    findings = runner.run(engine)

    temporal = [f for f in findings if f.rule_id == "R201"]
    assert len(temporal) == 1
    assert temporal[0].severity == Severity.ERROR


def test_contradiction_detection():
    engine = AttackGraphEngine()
    obs = Observation(
        id="obs-mfa-denied",
        source_id="src-azure-ad",
        timestamp=datetime.now(timezone.utc),
        category="auth",
        description="MFA Push Notification was explicitly DENIED by user",
    )
    step = AttackStep(
        id="step-bypass",
        title="Attacker Bypassed MFA",
    )
    engine.add_observation(obs)
    engine.add_attack_step(step)
    engine.add_edge("obs-mfa-denied", "step-bypass", EdgeType.CONTRADICTS)

    runner = RuleEngineRunner()
    findings = runner.run(engine)

    contra = [f for f in findings if f.rule_id == "R501"]
    assert len(contra) == 1
    assert contra[0].severity == Severity.ERROR


def test_candidate_paths_and_uncertainty_evaluation():
    engine = AttackGraphEngine()
    step1 = AttackStep(id="step-1", title="Credential Dump")
    step2 = AttackStep(id="step-2", title="Lateral Movement")
    step3 = AttackStep(id="step-3", title="Data Exfiltration")

    engine.add_attack_step(step1)
    engine.add_attack_step(step2)
    engine.add_attack_step(step3)

    engine.add_edge("step-1", "step-2", EdgeType.ENABLES, edge_id="e1")
    engine.add_edge("step-2", "step-3", EdgeType.ENABLES, edge_id="e2")

    # Only step 1 has direct observation
    obs1 = Observation(
        id="obs-lsass",
        source_id="sysmon",
        timestamp=datetime.now(timezone.utc),
        category="endpoint",
        description="LSASS memory dump detected",
    )
    engine.add_observation(obs1)
    engine.add_edge("step-1", "obs-lsass", EdgeType.OBSERVED_AS)

    paths = engine.find_candidate_paths("step-1", "step-3")
    assert len(paths) == 1
    path = paths[0]
    # Partially supported because step-2 and step-3 lack observations
    assert path.status == PathStatus.PARTIALLY_SUPPORTED
    assert "obs-lsass" in path.supporting_observations
    assert len(path.missing_evidence) >= 2
