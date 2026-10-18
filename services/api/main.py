"""Production-grade FastAPI application for AttackPath Intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from packages.attack_mapper.kb import AttackKnowledgeBase
from packages.attack_mapper.mapper import TechniqueMapper
from packages.evidence.normalizer import EvidenceNormalizer
from packages.reasoning_engine import AttackPathReasoningEngine
from packages.reporting.html_report import HTMLReportGenerator
from packages.schemas.models import (
    AnalysisResult,
    AttackGraphExport,
    CandidatePath,
    Finding,
    Observation,
    ReviewStatus,
    Scenario,
    ScenarioBundle,
    Technique,
)

app = FastAPI(
    title="AttackPath Intelligence API",
    description="Deterministic attack-chain reasoning engine and MITRE ATT&CK validation service.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage cache (persisted per scenario ID)
SCENARIOS: Dict[str, Scenario] = {}
BUNDLES: Dict[str, ScenarioBundle] = {}
RESULTS: Dict[str, AnalysisResult] = {}
REVIEWS: Dict[str, Dict[str, Any]] = {}

# Singletons
attack_kb = AttackKnowledgeBase()
reasoning_engine = AttackPathReasoningEngine(kb=attack_kb)

# Initialize database tables
from packages.database.session import SessionLocal, get_db, init_db
from packages.database.repository import AttackPathRepository
from fastapi import Depends
from sqlalchemy.orm import Session

try:
    init_db()
except Exception as e:
    pass


# -------------------------------------------------------------------------
# Request / Response Models
# -------------------------------------------------------------------------

class CreateScenarioRequest(BaseModel):
    id: str
    name: str
    description: str = ""
    objective: str = ""


class UploadEvidenceRequest(BaseModel):
    source_type: str = Field(description="json_bundle or csv_log")
    content: str
    source_name: Optional[str] = "upload"


class ReviewDecisionRequest(BaseModel):
    decision: ReviewStatus
    reviewer: str
    rationale: str


# -------------------------------------------------------------------------
# Endpoints
# -------------------------------------------------------------------------

@app.get("/health", tags=["System"])
def health_check() -> Dict[str, str]:
    return {"status": "healthy", "service": "AttackPath Intelligence", "version": "1.0.0"}


@app.post("/api/v1/scenarios", response_model=Scenario, status_code=status.HTTP_201_CREATED, tags=["Scenarios"])
def create_scenario(req: CreateScenarioRequest, db: Session = Depends(get_db)) -> Scenario:
    if req.id in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Scenario with ID '{req.id}' already exists.")

    scen = Scenario(
        id=req.id,
        name=req.name,
        description=req.description,
        objective=req.objective,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    SCENARIOS[req.id] = scen
    BUNDLES[req.id] = ScenarioBundle(scenario=scen)

    repo = AttackPathRepository(db)
    repo.create_or_update_scenario(scen)
    return scen


@app.get("/api/v1/scenarios", response_model=List[Scenario], tags=["Scenarios"])
def list_scenarios(db: Session = Depends(get_db)) -> List[Scenario]:
    repo = AttackPathRepository(db)
    db_scens = repo.list_scenarios()
    if db_scens:
        for s in db_scens:
            if s.id not in SCENARIOS:
                SCENARIOS[s.id] = Scenario(
                    id=s.id,
                    name=s.name,
                    description=s.description or "",
                    objective=s.objective or "",
                    created_at=s.created_at,
                    updated_at=s.updated_at,
                )
    return list(SCENARIOS.values())


@app.get("/api/v1/scenarios/{scenario_id}", response_model=Scenario, tags=["Scenarios"])
def get_scenario(scenario_id: str, db: Session = Depends(get_db)) -> Scenario:
    if scenario_id in SCENARIOS:
        return SCENARIOS[scenario_id]
    repo = AttackPathRepository(db)
    s = repo.get_scenario(scenario_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scenario not found")
    scen = Scenario(
        id=s.id,
        name=s.name,
        description=s.description or "",
        objective=s.objective or "",
        created_at=s.created_at,
        updated_at=s.updated_at,
    )
    SCENARIOS[s.id] = scen
    return scen


@app.post("/api/v1/scenarios/{scenario_id}/evidence", tags=["Evidence"])
def upload_evidence(scenario_id: str, req: UploadEvidenceRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found")

    repo = AttackPathRepository(db)
    if req.source_type == "json_bundle":
        bundle = EvidenceNormalizer.from_json_bundle(req.content, source_name=req.source_name or "uploaded_json")
        bundle.scenario.id = scenario_id
        BUNDLES[scenario_id] = bundle
        repo.save_bundle(bundle)
        return {
            "status": "success",
            "assets_loaded": len(bundle.assets),
            "observations_loaded": len(bundle.observations),
            "hypotheses_loaded": len(bundle.hypotheses),
        }
    elif req.source_type == "csv_log":
        observations = EvidenceNormalizer.from_csv_logs(req.content, source_name=req.source_name or "uploaded_csv")
        bundle = BUNDLES.get(scenario_id, ScenarioBundle(scenario=SCENARIOS[scenario_id]))
        bundle.observations.extend(observations)
        BUNDLES[scenario_id] = bundle
        repo.save_bundle(bundle)
        return {"status": "success", "observations_loaded": len(observations)}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported source_type: {req.source_type}")


@app.post("/api/v1/scenarios/{scenario_id}/analyze", response_model=AnalysisResult, tags=["Analysis"])
def analyze_scenario(scenario_id: str, db: Session = Depends(get_db)) -> AnalysisResult:
    if scenario_id not in BUNDLES:
        raise HTTPException(status_code=404, detail="Scenario bundle not found or no evidence uploaded.")

    bundle = BUNDLES[scenario_id]
    result = reasoning_engine.analyze_bundle(bundle)
    RESULTS[scenario_id] = result

    repo = AttackPathRepository(db)
    repo.save_analysis_result(result)
    return result


@app.get("/api/v1/scenarios/{scenario_id}/graph", response_model=AttackGraphExport, tags=["Analysis"])
def get_scenario_graph(scenario_id: str) -> AttackGraphExport:
    if scenario_id not in RESULTS:
        raise HTTPException(status_code=404, detail="Analysis has not yet been executed for this scenario.")
    return RESULTS[scenario_id].graph


@app.get("/api/v1/scenarios/{scenario_id}/findings", response_model=List[Finding], tags=["Analysis"])
def get_scenario_findings(scenario_id: str) -> List[Finding]:
    if scenario_id not in RESULTS:
        raise HTTPException(status_code=404, detail="Analysis has not yet been executed for this scenario.")
    return RESULTS[scenario_id].findings


@app.get("/api/v1/scenarios/{scenario_id}/paths", response_model=List[CandidatePath], tags=["Analysis"])
def get_scenario_paths(scenario_id: str) -> List[CandidatePath]:
    if scenario_id not in RESULTS:
        raise HTTPException(status_code=404, detail="Analysis has not yet been executed for this scenario.")
    return RESULTS[scenario_id].candidate_paths


@app.get("/api/v1/techniques", response_model=List[Technique], tags=["KnowledgeBase"])
def search_techniques(
    q: Optional[str] = Query(None, description="Search query"),
    tactic: Optional[str] = Query(None, description="ATT&CK tactic filter"),
    platform: Optional[str] = Query(None, description="Platform filter"),
    limit: int = Query(20, ge=1, le=100),
) -> List[Technique]:
    if q:
        return attack_kb.search(query=q, tactic=tactic, platform=platform, limit=limit)
    all_techs = attack_kb.list_all()
    if tactic:
        all_techs = [t for t in all_techs if any(tactic.lower() == tac.lower() for tac in t.tactics)]
    if platform:
        all_techs = [t for t in all_techs if any(platform.lower() == p.lower() for p in t.platforms)]
    return all_techs[:limit]


@app.post("/api/v1/findings/{finding_id}/review", tags=["Review"])
def record_review(finding_id: str, req: ReviewDecisionRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    REVIEWS[finding_id] = {
        "finding_id": finding_id,
        "decision": req.decision.value,
        "reviewer": req.reviewer,
        "rationale": req.rationale,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    repo = AttackPathRepository(db)
    repo.record_review(
        finding_id=finding_id,
        reviewer=req.reviewer,
        decision=req.decision,
        rationale=req.rationale,
    )
    return {"status": "recorded", "review": REVIEWS[finding_id]}


@app.get("/api/v1/scenarios/{scenario_id}/export", tags=["Export"])
def export_scenario_report(
    scenario_id: str,
    format: str = Query("json", description="json or html"),
) -> Response:
    if scenario_id not in RESULTS:
        raise HTTPException(status_code=404, detail="Analysis has not yet been executed for this scenario.")

    result = RESULTS[scenario_id]

    if format.lower() == "html":
        html_content = HTMLReportGenerator.generate(result)
        return Response(content=html_content, media_type="text/html")
    else:
        return Response(
            content=result.model_dump_json(indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={scenario_id}_analysis.json"},
        )
