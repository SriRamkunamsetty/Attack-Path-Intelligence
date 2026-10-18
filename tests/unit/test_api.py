"""Unit tests for FastAPI endpoints."""

from fastapi.testclient import TestClient
import pytest
from services.api.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_scenario_creation_and_analysis_flow():
    # 1. Create scenario
    create_res = client.post(
        "/api/v1/scenarios",
        json={
            "id": "scen-test-01",
            "name": "Test Incident Scenario",
            "description": "Simulation of cloud credential compromise",
            "objective": "Evaluate reasoning engine",
        },
    )
    assert create_res.status_code == 201

    # 2. Upload JSON bundle evidence
    sample_bundle_json = """{
      "scenario": {"id": "scen-test-01", "name": "Test Incident"},
      "assets": [
        {"id": "usr-alice", "name": "alice@corp.internal", "asset_type": "identity"},
        {"id": "cloud-s3", "name": "finance-records-bucket", "asset_type": "cloud_resource"}
      ],
      "observations": [
        {
          "id": "obs-1",
          "timestamp": "2026-10-18T10:00:00Z",
          "category": "auth",
          "description": "Failed authentication attempt followed by password spray alert",
          "asset_id": "usr-alice",
          "actor_identity": "alice@corp.internal"
        },
        {
          "id": "obs-2",
          "timestamp": "2026-10-18T10:05:00Z",
          "category": "cloud",
          "description": "Direct read access from S3 cloud storage bucket",
          "asset_id": "cloud-s3",
          "actor_identity": "alice@corp.internal"
        }
      ],
      "hypotheses": [
        {"id": "step-1", "title": "Brute Force Password Spray", "stage": "credential-access"},
        {"id": "step-2", "title": "Data from Cloud Storage", "stage": "collection"}
      ],
      "controls": [],
      "explicit_edges": [
        {"id": "e1", "source": "step-1", "target": "step-2", "edge_type": "ENABLES"},
        {"id": "e2", "source": "step-1", "target": "obs-1", "edge_type": "OBSERVED_AS"},
        {"id": "e3", "source": "step-2", "target": "obs-2", "edge_type": "OBSERVED_AS"}
      ]
    }"""

    upload_res = client.post(
        "/api/v1/scenarios/scen-test-01/evidence",
        json={"source_type": "json_bundle", "content": sample_bundle_json},
    )
    assert upload_res.status_code == 200

    # 3. Analyze scenario
    analyze_res = client.post("/api/v1/scenarios/scen-test-01/analyze")
    assert analyze_res.status_code == 200
    res_data = analyze_res.json()
    assert res_data["scenario_id"] == "scen-test-01"
    assert "graph" in res_data
    assert "candidate_paths" in res_data
    assert len(res_data["candidate_paths"]) >= 1

    # 4. Check findings
    findings_res = client.get("/api/v1/scenarios/scen-test-01/findings")
    assert findings_res.status_code == 200
    assert isinstance(findings_res.json(), list)

    # 5. Check candidate paths
    paths_res = client.get("/api/v1/scenarios/scen-test-01/paths")
    assert paths_res.status_code == 200
    assert len(paths_res.json()) >= 1

    # 6. Test export HTML
    export_res = client.get("/api/v1/scenarios/scen-test-01/export?format=html")
    assert export_res.status_code == 200
    assert "AttackPath Intelligence Report" in export_res.text


def test_technique_search():
    res = client.get("/api/v1/techniques?q=lsass")
    assert res.status_code == 200
    results = res.json()
    assert len(results) >= 1
    assert results[0]["technique_id"] == "T1003.001"
