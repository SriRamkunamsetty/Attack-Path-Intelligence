"""Live end-to-end integration test verifying running API, database, and reasoning engine."""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone


def test_live_api():
    print("=" * 70)
    print(" LIVE END-TO-END SYSTEM INTEGRATION VERIFICATION")
    print("=" * 70)

    # 1. Health check
    req = urllib.request.urlopen("http://localhost:8000/health")
    assert req.status == 200
    health = json.loads(req.read().decode())
    print(f"[1/5] Health Check: SUCCESS -> {health}")

    # 2. Technique search
    req = urllib.request.urlopen("http://localhost:8000/api/v1/techniques?q=lsass")
    assert req.status == 200
    techs = json.loads(req.read().decode())
    assert len(techs) >= 1
    print(f"[2/5] MITRE Technique Search: SUCCESS -> Found {techs[0]['technique_id']}: {techs[0]['name']}")

    # 3. Create scenario
    scenario_payload = json.dumps({
        "id": "LIVE-TEST-001",
        "name": "Live Enterprise Incident Test",
        "description": "Verifying live API and DB persistence",
        "objective": "Verify end-to-end stack",
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://localhost:8000/api/v1/scenarios",
        data=scenario_payload,
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 201
    scen = json.loads(resp.read().decode())
    print(f"[3/5] Scenario Creation & DB Registration: SUCCESS -> ID {scen['id']}")

    # 4. Upload evidence & analyze
    sample_bundle = {
        "scenario": {"id": "LIVE-TEST-001", "name": "Live Incident"},
        "assets": [
            {"id": "usr-john", "name": "john@corp.internal", "asset_type": "identity"},
            {"id": "srv-sql", "name": "prod-sql-cluster", "asset_type": "database"}
        ],
        "observations": [
            {
                "id": "obs-live-1",
                "timestamp": "2026-10-18T10:00:00Z",
                "category": "auth",
                "description": "Multiple failed logins followed by success for john@corp.internal",
                "actor_identity": "john@corp.internal"
            },
            {
                "id": "obs-live-2",
                "timestamp": "2026-10-18T10:05:00Z",
                "category": "endpoint",
                "description": "PowerShell command execution dumping sql credentials",
                "actor_identity": "john@corp.internal"
            }
        ],
        "hypotheses": [
            {"id": "step-live-1", "title": "Brute Force Password Spray", "stage": "credential-access"},
            {"id": "step-live-2", "title": "PowerShell Execution", "stage": "execution"}
        ],
        "controls": [],
        "explicit_edges": [
            {"id": "e-live-1", "source": "step-live-1", "target": "step-live-2", "edge_type": "ENABLES"},
            {"id": "e-live-2", "source": "step-live-1", "target": "obs-live-1", "edge_type": "OBSERVED_AS"},
            {"id": "e-live-3", "source": "step-live-2", "target": "obs-live-2", "edge_type": "OBSERVED_AS"}
        ]
    }

    evidence_payload = json.dumps({
        "source_type": "json_bundle",
        "content": json.dumps(sample_bundle),
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://localhost:8000/api/v1/scenarios/LIVE-TEST-001/evidence",
        data=evidence_payload,
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    print("[4/5] Evidence Ingestion & Normalization: SUCCESS")

    # 5. Execute Analysis
    req = urllib.request.Request(
        "http://localhost:8000/api/v1/scenarios/LIVE-TEST-001/analyze",
        data=b"",
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    result = json.loads(resp.read().decode())
    print(f"[5/5] Reasoning Engine Execution: SUCCESS")
    print(f"      - Evidence Coverage: {result['metrics']['evidence_coverage_ratio'] * 100:.1f}%")
    print(f"      - Graph Nodes: {result['metrics']['total_nodes']}")
    print(f"      - Findings Identified: {len(result['findings'])}")
    print(f"      - Candidate Paths: {len(result['candidate_paths'])}")
    print(f"      - Path Status: {result['candidate_paths'][0]['status'].upper()}")

    # 6. Verify Next.js web application
    web_req = urllib.request.urlopen("http://localhost:3001")
    assert web_req.status == 200
    print("[+] Next.js React Flow Frontend: SUCCESS (HTTP 200 on http://localhost:3001)")

    print("=" * 70)
    print(" ALL LIVE INTEGRATION TESTS PASSED! FULL STACK IS OPERATIONAL.")
    print("=" * 70)


if __name__ == "__main__":
    test_live_api()
