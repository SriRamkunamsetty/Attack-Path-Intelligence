"""Interactive end-to-end incident walkthrough script for AttackPath Intelligence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

# Ensure repository root is on sys.path
root_dir = Path(__file__).resolve().parents[1]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from packages.reasoning_engine import AttackPathReasoningEngine
from packages.reporting.html_report import HTMLReportGenerator
from packages.schemas.models import (
    Asset,
    AssetType,
    AttackStep,
    ControlState,
    EdgeType,
    GraphEdge,
    Observation,
    Scenario,
    ScenarioBundle,
    SecurityControl,
)


def main() -> None:
    print("\n" + "=" * 70)
    print(" ATTACKPATH INTELLIGENCE — END-TO-END INCIDENT REASONING DEMO")
    print("=" * 70)

    t0 = datetime(2026, 10, 18, 14, 0, 0, tzinfo=timezone.utc)

    # Construct the Enterprise Incident from Section 2 of Specification:
    # 1. Unusual employee account login
    # 2. Account accesses internal application
    # 3. Application records access to sensitive resource
    # 4. Security alert identifies possible data policy violation
    # Plus: Contradictory evidence (Admin confirmed standard batch job or MFA verification)
    bundle = ScenarioBundle(
        scenario=Scenario(
            id="INC-2026-8812",
            name="Suspected Employee Account Misuse & Sensitive Data Access",
            description="Reconstructing possible attack chain from auth logs, proxy events, and S3 data records.",
            objective="Distinguish between unauthorized compromise, administrative error, and false positive.",
            created_at=t0,
            updated_at=t0,
        ),
        assets=[
            Asset(id="usr-bob", name="bob.miller@megacorp.internal", asset_type=AssetType.IDENTITY),
            Asset(id="app-billing", name="BillingPortal-Internal", asset_type=AssetType.APPLICATION),
            Asset(id="db-vault", name="FinancialRecords-EncryptedBucket", asset_type=AssetType.CLOUD_RESOURCE),
        ],
        observations=[
            Observation(
                id="obs-101",
                source_id="azure_ad_signin",
                timestamp=t0,
                category="auth",
                description="Unusual sign-in from foreign IP 185.220.101.5 for bob.miller@megacorp.internal",
                actor_identity="bob.miller@megacorp.internal",
                asset_id="usr-bob",
            ),
            Observation(
                id="obs-102",
                source_id="app_proxy",
                timestamp=t0 + timedelta(minutes=4),
                category="endpoint",
                description="PowerShell script executed Get-Credential and web session handoff to BillingPortal",
                actor_identity="bob.miller@megacorp.internal",
                asset_id="app-billing",
            ),
            Observation(
                id="obs-103",
                source_id="cloudtrail",
                timestamp=t0 + timedelta(minutes=10),
                category="cloud",
                description="GetObject bulk export of 12,000 records from FinancialRecords-EncryptedBucket",
                actor_identity="bob.miller@megacorp.internal",
                asset_id="db-vault",
            ),
        ],
        hypotheses=[
            AttackStep(
                id="step-1",
                title="Credential Access / Account Takeover",
                stage="initial-access",
                timestamp=t0,
            ),
            AttackStep(
                id="step-2",
                title="Execution via PowerShell Web Request",
                stage="execution",
                timestamp=t0 + timedelta(minutes=4),
            ),
            AttackStep(
                id="step-3",
                title="Cloud Storage Exfiltration",
                stage="collection",
                timestamp=t0 + timedelta(minutes=10),
            ),
        ],
        controls=[
            SecurityControl(
                id="ctrl-mfa",
                name="Conditional Access & MFA Policy",
                category="preventive",
                state=ControlState.CONFIRMED_PRESENT,
            ),
            SecurityControl(
                id="ctrl-dlp",
                name="Cloud DLP Sensitive Object Access Monitoring",
                category="detective",
                state=ControlState.CONFIRMED_PRESENT,
            ),
        ],
        explicit_edges=[
            GraphEdge(id="e1", source="step-1", target="step-2", edge_type=EdgeType.ENABLES),
            GraphEdge(id="e2", source="step-2", target="step-3", edge_type=EdgeType.ENABLES),
            GraphEdge(id="e3", source="step-1", target="obs-101", edge_type=EdgeType.OBSERVED_AS),
            GraphEdge(id="e4", source="step-2", target="obs-102", edge_type=EdgeType.OBSERVED_AS),
            GraphEdge(id="e5", source="step-3", target="obs-103", edge_type=EdgeType.OBSERVED_AS),
            GraphEdge(id="e6", source="step-1", target="ctrl-mfa", edge_type=EdgeType.MITIGATED_BY),
            GraphEdge(id="e7", source="step-3", target="ctrl-dlp", edge_type=EdgeType.MITIGATED_BY),
        ],
    )

    print("\n[+] Ingested Scenario:")
    print(f"    - ID: {bundle.scenario.id}")
    print(f"    - Name: {bundle.scenario.name}")
    print(f"    - Observations: {len(bundle.observations)}")
    print(f"    - Hypotheses: {len(bundle.hypotheses)}")
    print(f"    - Controls: {len(bundle.controls)}")

    # Execute Reasoning
    engine = AttackPathReasoningEngine()
    result = engine.analyze_bundle(bundle)

    print("\n[+] Reasoning Results:")
    print(f"    - Evidence Coverage: {result.metrics['evidence_coverage_ratio'] * 100:.1f}%")
    print(f"    - Findings Identified: {result.metrics['findings_count']['total']}")
    print(f"    - Candidate Paths: {len(result.candidate_paths)}")

    print("\n[+] Candidate Path Assessment:")
    for path in result.candidate_paths:
        print(f"    * Path: {' -> '.join(path.step_ids)}")
        print(f"      Status: {path.status.value.upper()}")
        print(f"      Rationale: {path.confidence_rationale}")
        print(f"      Discriminator telemetry needed: {', '.join(path.discriminator_evidence[:2])}")

    print("\n[+] MITRE ATT&CK Mappings:")
    for m in result.technique_mappings:
        print(f"    * [{m.technique_id}] {m.technique_name} (Target: {m.target_id}, Status: {m.status.value})")

    # Generate Reports
    reports_dir = root_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    html_file = reports_dir / f"{bundle.scenario.id}_report.html"
    json_file = reports_dir / f"{bundle.scenario.id}_analysis.json"

    html_content = HTMLReportGenerator.generate(result)
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    with open(json_file, "w", encoding="utf-8") as f:
        f.write(result.model_dump_json(indent=2))

    print(f"\n[+] Interactive HTML Report written to: {html_file}")
    print(f"[+] Machine-readable JSON Export written to: {json_file}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
