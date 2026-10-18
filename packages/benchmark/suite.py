"""Canonical 30-scenario benchmark suite for AttackPath Intelligence evaluation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

from packages.benchmark.models import BenchmarkGroundTruth, BenchmarkScenario
from packages.schemas.models import (
    Asset,
    AssetType,
    AttackStep,
    ControlState,
    EdgeType,
    GraphEdge,
    Observation,
    PathStatus,
    Scenario,
    ScenarioBundle,
    SecurityControl,
)


def create_30_scenarios() -> List[BenchmarkScenario]:
    """Builds the 30 carefully labeled benchmark scenarios across 6 archetypes."""
    base_time = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
    scenarios: List[BenchmarkScenario] = []

    # -------------------------------------------------------------------------
    # Category 1: Golden Path (Scenarios 1 - 5)
    # Fully evidenced, legitimate attack paths where every step has direct observations.
    # -------------------------------------------------------------------------
    for i in range(1, 6):
        scen_id = f"BENCH-GP-{i:02d}"
        t1 = base_time + timedelta(minutes=i * 10)
        t2 = t1 + timedelta(minutes=2)
        t3 = t2 + timedelta(minutes=3)

        bundle = ScenarioBundle(
            scenario=Scenario(
                id=scen_id,
                name=f"Golden Path Case {i}: Multi-stage Compromise",
                description="Fully observed attack chain with complete telemetry.",
                objective="Detect valid attack path without false contradictions.",
                created_at=base_time,
                updated_at=base_time,
            ),
            assets=[
                Asset(id=f"host-gp-{i}", name=f"Workstation-{i}", asset_type=AssetType.HOST),
                Asset(id=f"srv-gp-{i}", name=f"Database-{i}", asset_type=AssetType.DATABASE),
            ],
            observations=[
                Observation(
                    id=f"obs-gp-{i}-1",
                    source_id="edr",
                    timestamp=t1,
                    category="endpoint",
                    description=f"PowerShell executed encoded download cradle on Workstation-{i}",
                    asset_id=f"host-gp-{i}",
                    actor_identity="attacker_c2",
                ),
                Observation(
                    id=f"obs-gp-{i}-2",
                    source_id="edr",
                    timestamp=t2,
                    category="endpoint",
                    description=f"LSASS memory dump detected by sysmon on Workstation-{i}",
                    asset_id=f"host-gp-{i}",
                    actor_identity="SYSTEM",
                ),
                Observation(
                    id=f"obs-gp-{i}-3",
                    source_id="network",
                    timestamp=t3,
                    category="network",
                    description=f"Inbound RDP port 3389 connection from Workstation-{i} to Database-{i}",
                    asset_id=f"srv-gp-{i}",
                    actor_identity="DomainAdmin",
                ),
            ],
            hypotheses=[
                AttackStep(id=f"step-gp-{i}-1", title="PowerShell Script Execution", stage="execution", timestamp=t1),
                AttackStep(id=f"step-gp-{i}-2", title="OS Credential Dumping LSASS", stage="credential-access", timestamp=t2),
                AttackStep(id=f"step-gp-{i}-3", title="RDP Lateral Movement", stage="lateral-movement", timestamp=t3),
            ],
            controls=[
                SecurityControl(id=f"ctrl-gp-{i}", name="EDR Block Mode", category="preventive", state=ControlState.RECOMMENDED)
            ],
            explicit_edges=[
                GraphEdge(id=f"e-gp-{i}-1", source=f"step-gp-{i}-1", target=f"step-gp-{i}-2", edge_type=EdgeType.ENABLES),
                GraphEdge(id=f"e-gp-{i}-2", source=f"step-gp-{i}-2", target=f"step-gp-{i}-3", edge_type=EdgeType.ENABLES),
                GraphEdge(id=f"e-gp-{i}-3", source=f"step-gp-{i}-1", target=f"obs-gp-{i}-1", edge_type=EdgeType.OBSERVED_AS),
                GraphEdge(id=f"e-gp-{i}-4", source=f"step-gp-{i}-2", target=f"obs-gp-{i}-2", edge_type=EdgeType.OBSERVED_AS),
                GraphEdge(id=f"e-gp-{i}-5", source=f"step-gp-{i}-3", target=f"obs-gp-{i}-3", edge_type=EdgeType.OBSERVED_AS),
            ],
        )
        scenarios.append(
            BenchmarkScenario(
                id=scen_id,
                title=f"Golden Path {i}",
                category="golden_path",
                description="All attack steps are backed by direct telemetry. Status should be SUPPORTED.",
                bundle=bundle,
                ground_truth=BenchmarkGroundTruth(
                    expected_edge_ids=[f"e-gp-{i}-1", f"e-gp-{i}-2"],
                    expected_path_status=PathStatus.SUPPORTED,
                    expected_finding_rule_ids=[],
                    expected_technique_ids=["T1059.001", "T1003.001", "T1021.001"],
                    has_contradiction=False,
                    rationale="Complete telemetry confirms execution, credential dump, and lateral movement.",
                ),
            )
        )

    # -------------------------------------------------------------------------
    # Category 2: Contradiction Cases (Scenarios 6 - 10)
    # Scenarios where verified security evidence directly contradicts a hypothesized attack step.
    # -------------------------------------------------------------------------
    for i in range(6, 11):
        scen_id = f"BENCH-CT-{i:02d}"
        t1 = base_time + timedelta(minutes=i * 10)
        t2 = t1 + timedelta(minutes=1)

        bundle = ScenarioBundle(
            scenario=Scenario(
                id=scen_id,
                name=f"Contradiction Case {i}: MFA Explicit Deny",
                description="Attacker claims account access, but MFA log proves push challenge was explicitly rejected.",
                created_at=base_time,
                updated_at=base_time,
            ),
            assets=[
                Asset(id=f"usr-ct-{i}", name=f"victim{i}@corp.internal", asset_type=AssetType.IDENTITY),
            ],
            observations=[
                Observation(
                    id=f"obs-ct-{i}-deny",
                    source_id="azure_ad",
                    timestamp=t1,
                    category="auth",
                    description=f"MFA Push Notification denied with fraud alert by user victim{i}@corp.internal",
                    actor_identity=f"victim{i}@corp.internal",
                ),
            ],
            hypotheses=[
                AttackStep(id=f"step-ct-{i}-spray", title="Password Spraying", stage="credential-access", timestamp=t1),
                AttackStep(id=f"step-ct-{i}-bypass", title="MFA Bypass Success", stage="initial-access", timestamp=t2),
            ],
            controls=[],
            explicit_edges=[
                GraphEdge(id=f"e-ct-{i}-1", source=f"step-ct-{i}-spray", target=f"step-ct-{i}-bypass", edge_type=EdgeType.ENABLES),
                GraphEdge(id=f"e-ct-{i}-contra", source=f"obs-ct-{i}-deny", target=f"step-ct-{i}-bypass", edge_type=EdgeType.CONTRADICTS),
            ],
        )
        scenarios.append(
            BenchmarkScenario(
                id=scen_id,
                title=f"Contradicted MFA {i}",
                category="contradiction",
                description="Verified observation directly contradicts bypass claim.",
                bundle=bundle,
                ground_truth=BenchmarkGroundTruth(
                    expected_edge_ids=[f"e-ct-{i}-1"],
                    expected_path_status=PathStatus.CONTRADICTED,
                    expected_finding_rule_ids=["R501"],
                    expected_technique_ids=[],
                    has_contradiction=True,
                    rationale="MFA fraud alert directly refutes bypass hypothesis.",
                ),
            )
        )

    # -------------------------------------------------------------------------
    # Category 3: Prerequisite & Temporal Violations (Scenarios 11 - 15)
    # Scenarios violating temporal sequence or missing prerequisite conditions.
    # -------------------------------------------------------------------------
    for i in range(11, 16):
        scen_id = f"BENCH-PV-{i:02d}"
        t_early = base_time + timedelta(minutes=i * 5)
        t_late = t_early + timedelta(hours=2)

        bundle = ScenarioBundle(
            scenario=Scenario(
                id=scen_id,
                name=f"Temporal Violation Case {i}: Reversed Timeline",
                description="Hypothesized causal transition where prerequisite occurs after enabled action.",
                created_at=base_time,
                updated_at=base_time,
            ),
            assets=[Asset(id=f"host-pv-{i}", name=f"Host-{i}", asset_type=AssetType.HOST)],
            observations=[],
            hypotheses=[
                AttackStep(id=f"step-pv-{i}-later", title="Exfiltration to Cloud", stage="exfiltration", timestamp=t_early),
                AttackStep(id=f"step-pv-{i}-earlier", title="Initial Phishing Payload", stage="initial-access", timestamp=t_late),
            ],
            controls=[],
            explicit_edges=[
                # step-pv-earlier (t_late) claimed to ENABLES step-pv-later (t_early) -> Illegal!
                GraphEdge(id=f"e-pv-{i}-rev", source=f"step-pv-{i}-earlier", target=f"step-pv-{i}-later", edge_type=EdgeType.ENABLES),
            ],
        )
        scenarios.append(
            BenchmarkScenario(
                id=scen_id,
                title=f"Prerequisite Temporal Violation {i}",
                category="prerequisite_gap",
                description="Temporal order violation must trigger R201 error.",
                bundle=bundle,
                ground_truth=BenchmarkGroundTruth(
                    expected_edge_ids=[f"e-pv-{i}-rev"],
                    expected_path_status=PathStatus.UNSUBSTANTIATED,
                    expected_finding_rule_ids=["R201"],
                    expected_technique_ids=[],
                    has_contradiction=False,
                    rationale="A step at timestamp t_late cannot enable a step at t_early.",
                ),
            )
        )

    # -------------------------------------------------------------------------
    # Category 4: Telemetry Gaps / Missing Evidence (Scenarios 16 - 20)
    # Attack paths where critical intermediate steps lack supporting observations.
    # -------------------------------------------------------------------------
    for i in range(16, 21):
        scen_id = f"BENCH-TG-{i:02d}"
        t1 = base_time + timedelta(minutes=i * 10)
        t2 = t1 + timedelta(minutes=5)
        t3 = t2 + timedelta(minutes=5)

        bundle = ScenarioBundle(
            scenario=Scenario(
                id=scen_id,
                name=f"Telemetry Gap Case {i}: Missing Lateral Movement Logs",
                description="Initial login and final exfiltration observed, but intermediate pivot lacks telemetry.",
                created_at=base_time,
                updated_at=base_time,
            ),
            assets=[
                Asset(id=f"host-tg-{i}", name=f"Workstation-{i}", asset_type=AssetType.HOST),
                Asset(id=f"srv-tg-{i}", name=f"FileServer-{i}", asset_type=AssetType.HOST),
            ],
            observations=[
                Observation(
                    id=f"obs-tg-{i}-1",
                    source_id="auth_log",
                    timestamp=t1,
                    category="auth",
                    description="Unusual sign-in from external VPN IP",
                    actor_identity="analyst_test",
                ),
                Observation(
                    id=f"obs-tg-{i}-3",
                    source_id="proxy_log",
                    timestamp=t3,
                    category="network",
                    description="Large archive uploaded to external web service",
                    actor_identity="analyst_test",
                ),
            ],
            hypotheses=[
                AttackStep(id=f"step-tg-{i}-1", title="Initial Account Access", stage="initial-access", timestamp=t1),
                AttackStep(id=f"step-tg-{i}-2", title="Unobserved Lateral Movement to FileServer", stage="lateral-movement", timestamp=t2),
                AttackStep(id=f"step-tg-{i}-3", title="Data Exfiltration Over Web", stage="exfiltration", timestamp=t3),
            ],
            controls=[],
            explicit_edges=[
                GraphEdge(id=f"e-tg-{i}-1", source=f"step-tg-{i}-1", target=f"step-tg-{i}-2", edge_type=EdgeType.ENABLES),
                GraphEdge(id=f"e-tg-{i}-2", source=f"step-tg-{i}-2", target=f"step-tg-{i}-3", edge_type=EdgeType.ENABLES),
                GraphEdge(id=f"e-tg-{i}-obs1", source=f"step-tg-{i}-1", target=f"obs-tg-{i}-1", edge_type=EdgeType.OBSERVED_AS),
                GraphEdge(id=f"e-tg-{i}-obs3", source=f"step-tg-{i}-3", target=f"obs-tg-{i}-3", edge_type=EdgeType.OBSERVED_AS),
            ],
        )
        scenarios.append(
            BenchmarkScenario(
                id=scen_id,
                title=f"Telemetry Gap {i}",
                category="telemetry_gap",
                description="Intermediate step lacks observations. Status must be PARTIALLY_SUPPORTED with R601 finding.",
                bundle=bundle,
                ground_truth=BenchmarkGroundTruth(
                    expected_edge_ids=[f"e-tg-{i}-1", f"e-tg-{i}-2"],
                    expected_path_status=PathStatus.PARTIALLY_SUPPORTED,
                    expected_finding_rule_ids=["R601"],
                    expected_technique_ids=[],
                    has_contradiction=False,
                    rationale="Step 2 has no evidence link, indicating an investigative gap.",
                ),
            )
        )

    # -------------------------------------------------------------------------
    # Category 5: Ambiguous Admin Activity (Scenarios 21 - 25)
    # Routine administrative maintenance mimicking attack activity.
    # -------------------------------------------------------------------------
    for i in range(21, 26):
        scen_id = f"BENCH-AA-{i:02d}"
        t1 = base_time + timedelta(minutes=i * 10)
        t2 = t1 + timedelta(minutes=2)

        bundle = ScenarioBundle(
            scenario=Scenario(
                id=scen_id,
                name=f"Ambiguous Admin Case {i}: Scheduled Maintenance Script",
                description="Admin user executed remote PowerShell during documented maintenance window.",
                created_at=base_time,
                updated_at=base_time,
            ),
            assets=[Asset(id=f"host-aa-{i}", name=f"AdminPC-{i}", asset_type=AssetType.HOST)],
            observations=[
                Observation(
                    id=f"obs-aa-{i}-login",
                    source_id="auth",
                    timestamp=t1,
                    category="auth",
                    description="IT Admin sign-in from corporate jumpbox",
                    actor_identity=f"itadmin{i}@corp.internal",
                ),
                Observation(
                    id=f"obs-aa-{i}-ps",
                    source_id="endpoint",
                    timestamp=t2,
                    category="endpoint",
                    description="PowerShell script executed Get-Service diagnostics",
                    actor_identity=f"itadmin{i}@corp.internal",
                ),
            ],
            hypotheses=[
                AttackStep(id=f"step-aa-{i}-1", title="Valid Accounts Sign-in", stage="initial-access", timestamp=t1),
                AttackStep(id=f"step-aa-{i}-2", title="PowerShell Execution", stage="execution", timestamp=t2),
            ],
            controls=[],
            explicit_edges=[
                # Pure PRECEDES edge without proved malice
                GraphEdge(id=f"e-aa-{i}-prec", source=f"obs-aa-{i}-login", target=f"obs-aa-{i}-ps", edge_type=EdgeType.PRECEDES),
                GraphEdge(id=f"e-aa-{i}-en", source=f"step-aa-{i}-1", target=f"step-aa-{i}-2", edge_type=EdgeType.ENABLES),
                GraphEdge(id=f"e-aa-{i}-o1", source=f"step-aa-{i}-1", target=f"obs-aa-{i}-login", edge_type=EdgeType.OBSERVED_AS),
                GraphEdge(id=f"e-aa-{i}-o2", source=f"step-aa-{i}-2", target=f"obs-aa-{i}-ps", edge_type=EdgeType.OBSERVED_AS),
            ],
        )
        scenarios.append(
            BenchmarkScenario(
                id=scen_id,
                title=f"Ambiguous Admin {i}",
                category="ambiguous_admin",
                description="Temporal order alone without proof of malicious causation triggers R202.",
                bundle=bundle,
                ground_truth=BenchmarkGroundTruth(
                    expected_edge_ids=[f"e-aa-{i}-en"],
                    expected_path_status=PathStatus.SUPPORTED,
                    expected_finding_rule_ids=["R202"],
                    expected_technique_ids=["T1059.001"],
                    has_contradiction=False,
                    rationale="Legitimate admin script must surface discriminator questions.",
                ),
            )
        )

    # -------------------------------------------------------------------------
    # Category 6: Control Bypass & Defensive Failure (Scenarios 26 - 30)
    # Scenarios where an active preventive control is recorded as CONFIRMED_PRESENT, yet step occurred.
    # -------------------------------------------------------------------------
    for i in range(26, 31):
        scen_id = f"BENCH-CB-{i:02d}"
        t1 = base_time + timedelta(minutes=i * 10)

        bundle = ScenarioBundle(
            scenario=Scenario(
                id=scen_id,
                name=f"Control Bypass Case {i}: Endpoint Protection Evasion",
                description="LSASS dumping executed on host despite EDR blocking policy.",
                created_at=base_time,
                updated_at=base_time,
            ),
            assets=[Asset(id=f"host-cb-{i}", name=f"Workstation-{i}", asset_type=AssetType.HOST)],
            observations=[
                Observation(
                    id=f"obs-cb-{i}",
                    source_id="sysmon",
                    timestamp=t1,
                    category="endpoint",
                    description="LSASS memory dump completed successfully to minidump.dmp",
                    asset_id=f"host-cb-{i}",
                ),
            ],
            hypotheses=[
                AttackStep(id=f"step-cb-{i}", title="LSASS Memory Access", stage="credential-access", timestamp=t1),
            ],
            controls=[
                SecurityControl(
                    id=f"ctrl-cb-{i}",
                    name="EDR Credential Guard Protection",
                    category="preventive",
                    state=ControlState.CONFIRMED_PRESENT,
                    effectiveness_verified=True,
                )
            ],
            explicit_edges=[
                GraphEdge(id=f"e-cb-{i}-obs", source=f"step-cb-{i}", target=f"obs-cb-{i}", edge_type=EdgeType.OBSERVED_AS),
                GraphEdge(id=f"e-cb-{i}-mit", source=f"step-cb-{i}", target=f"ctrl-cb-{i}", edge_type=EdgeType.MITIGATED_BY),
            ],
        )
        scenarios.append(
            BenchmarkScenario(
                id=scen_id,
                title=f"Control Bypass {i}",
                category="control_bypassed",
                description="Active preventive control failed to prevent observed step, triggering R702.",
                bundle=bundle,
                ground_truth=BenchmarkGroundTruth(
                    expected_edge_ids=[],
                    expected_path_status=PathStatus.UNSUBSTANTIATED,
                    expected_finding_rule_ids=["R702"],
                    expected_technique_ids=["T1003.001"],
                    has_contradiction=False,
                    rationale="Confirmed present control did not prevent memory dump.",
                ),
            )
        )

    return scenarios
