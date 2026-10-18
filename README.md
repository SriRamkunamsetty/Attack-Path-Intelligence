# AttackPath Intelligence — Attack-Chain Reasoning Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-1.0.0-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Next.js 14](https://img.shields.io/badge/Next.js-14.2.35-black.svg?logo=next.js)](https://nextjs.org/)
[![React Flow](https://img.shields.io/badge/React_Flow-12.0-ff0072.svg)](https://reactflow.dev/)
[![SQLAlchemy 2.0](https://img.shields.io/badge/SQLAlchemy-2.0-red.svg)](https://www.sqlalchemy.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue.svg?logo=postgresql)](https://www.postgresql.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Tests: 13/13 Passed](https://img.shields.io/badge/Tests-13%20Passed-brightgreen.svg)]()
[![Benchmark: 30/30 Passed](https://img.shields.io/badge/Benchmark-100%25%20Passed-success.svg)]()

> **Industry-grade cybersecurity analysis platform and attack-chain reasoning engine that reconstructs possible attack paths from security observations, validates transitions, maps observed behavior to MITRE ATT&CK®, detects evidentiary contradictions, and explains defensive opportunities.**

---

## Table of Contents
1. [Project Overview & Mission](#1-project-overview--mission)
2. [The Problem It Solves](#2-the-problem-it-solves)
3. [Core Philosophy & Operating Principles](#3-core-philosophy--operating-principles)
4. [System Architecture & Multi-Layer Reasoning](#4-system-architecture--multi-layer-reasoning)
5. [Graph Ontology & Core Data Model](#5-graph-ontology--core-data-model)
6. [Deterministic Validation Rule Catalog (R100–R799)](#6-deterministic-validation-rule-catalog-r100r799)
7. [Alternative Attack Paths & Uncertainty Model](#7-alternative-attack-paths--uncertainty-model)
8. [MITRE ATT&CK® Knowledge Base & Mapper](#8-mitre-attck-knowledge-base--mapper)
9. [Durable Database Architecture & Alembic Migrations](#9-durable-database-architecture--alembic-migrations)
10. [Versioned REST API Specification (FastAPI v1)](#10-versioned-rest-api-specification-fastapi-v1)
11. [Next.js 14 + React Flow Frontend (6 Analyst Screens)](#11-nextjs-14--react-flow-frontend-6-analyst-screens)
12. [Evaluation Benchmark Suite (30 Ground-Truth Scenarios)](#12-evaluation-benchmark-suite-30-ground-truth-scenarios)
13. [Installation & Quickstart Guide](#13-installation--quickstart-guide)
14. [Testing & Verification](#14-testing--verification)
15. [Repository Structure](#15-repository-structure)

---

## 1. Project Overview & Mission

### Primary Objective
Convert raw or structured security observations into a **defensible, traceable attack-path analysis**.

### Target Users
- **Security Operations Center (SOC) Analysts & Threat Hunters**: Evaluate complex multi-stage incidents without jumping to false conclusions.
- **Red Team & Assessment Reviewers**: Verify whether a proposed attack path is logically valid and grounded in observed activity.
- **AI-Training & Evaluation Engineers**: Benchmark and evaluate AI reasoning on security telemetry with deterministic ground truth.

### Core Workflow
```text
Ingest Evidence ──► Normalize Events ──► Construct Attack Graph ──► Validate Transitions (Rules)
       ▲                                                                      │
       │                                                                      ▼
Export Report  ◄── Recommend Controls ◄── Assess Path Uncertainty ◄── Map MITRE ATT&CK
```

---

## 2. The Problem It Solves

Security evidence arrives in disconnected fragments across heterogeneous silos:
- An **authentication log** shows an unusual sign-in from an external IP.
- An **endpoint log** shows a PowerShell process executing.
- An **internal proxy event** shows communication with an internal portal.
- A **cloud audit log** records access to a sensitive data bucket.
- An **access-control policy** shows permission relationships.

### The Pitfall of Simple Graph Renderers
Traditional security tools simply connect these events sequentially on a canvas and declare that an attacker compromised the account and exfiltrated confidential data.

### The AttackPath Intelligence Approach
AttackPath Intelligence evaluates:
- **What each event actually proves** vs. what is inferred.
- Whether the observations belong to the **same session or distinct identities**.
- Whether **temporal proximity (`PRECEDES`) was mistakenly confused with causal enablement (`ENABLES`)**.
- Which intermediate links remain **unverified investigative gaps**.
- Whether verified telemetry **directly contradicts the attack hypothesis** (e.g., an MFA push was explicitly denied by the user).
- What alternative explanations exist (e.g., routine IT administration vs. attacker compromise).

---

## 3. Core Philosophy & Operating Principles

1. **Evidence vs. Inference**:
   - `Observation` nodes record verified empirical evidence (timestamps, source hashes, raw payloads).
   - `AttackStep` nodes represent proposed or inferred actions.
   - **The engine never presents an inferred attack step as a confirmed event.**
2. **`PRECEDES` $\neq$ `ENABLES`**:
   - Chronological sequence does not establish causality.
   - Event $A$ occurring before $B$ only warrants a `PRECEDES` edge unless verified prerequisites prove $A$ made $B$ possible (`ENABLES`).
3. **Absence of Evidence $\neq$ Evidence of Absence**:
   - A missing log record is treated as an *investigative gap* (`INFO` severity), not proof that the event did not occur.
   - A *contradiction* (`ERROR` severity) strictly requires affirmative conflicting evidence.
4. **Deterministic Core First, AI Second**:
   - Graph invariants, validation rules, and scoring are deterministic, transparent, and unit-tested.
   - LLMs can assist in interpreting narratives or drafting summaries, but cannot override hard constraints or fabricate evidence.

---

## 4. System Architecture & Multi-Layer Reasoning

```text
+-------------------------------------------------------------------------------+
|                           EVIDENCE INGESTION LAYER                            |
|  - JSON Incident Bundles | CSV Logs | IAM & Asset Configs | Narratives        |
|  - SHA-256 Provenance Hashing & Data-Quality Validation Checks                |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                       DIRECTED ATTACK GRAPH ENGINE                            |
|  - MultiDiGraph powered by NetworkX                                           |
|  - Nodes: Asset, Observation, AttackStep, Technique, Control, Finding         |
|  - Edges: PRECEDES, ENABLES, OBSERVED_AS, MAPPED_TO, MITIGATED_BY, CONTRADICTS|
+---------------------------------------+---------------------------------------+
                                        |
                    +-------------------+-------------------+
                    |                                       |
                    v                                       v
+---------------------------------------+   +-----------------------------------+
|     DETERMINISTIC RULE ENGINE         |   |      MITRE ATT&CK MAPPER          |
|  - Structural Integrity (R100s)       |   |  - STIX 2.1 Enterprise Matrix     |
|  - Chronological Consistency (R200s)  |   |  - Rule-Based Mapping Rationale   |
|  - Prerequisite Satisfaction (R300s)  |   |  - Missing Evidence Requirements  |
|  - Identity Consistency (R400s)       |   |  - Human Review Status Workflows  |
|  - Contradiction Detection (R500s)    |   +-----------------+-----------------+
|  - Evidence Coverage Gaps (R600s)     |                     |
|  - Defensive Controls (R700s)         |                     |
+-------------------+-------------------+                     |
                    |                                         |
                    +-------------------+---------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                     UNCERTAINTY & PATH REASONING ENGINE                       |
|  - Bounded traversal for candidate and alternative attack paths               |
|  - Status: SUPPORTED | PARTIALLY_SUPPORTED | UNSUBSTANTIATED | CONTRADICTED   |
|  - Discriminator telemetry identification for competing explanations          |
+---------------------------------------+---------------------------------------+
                                        |
                    +-------------------+-------------------+
                    |                                       |
                    v                                       v
+---------------------------------------+   +-----------------------------------+
|         PERSISTENT REPOSITORIES       |   |         FASTAPI REST SERVICE      |
|  - 11 SQLAlchemy 2.0 ORM Models       |   |  - Full REST API v1               |
|  - Dual SQLite & PostgreSQL Engines   |   |  - Standalone HTML Canvas Report  |
|  - Alembic Versioned Migrations       |   |  - Machine-Readable JSON Export   |
+---------------------------------------+   +-----------------+-----------------+
                                                              |
                                                              v
+-------------------------------------------------------------------------------+
|                     NEXT.JS 14 + REACT FLOW DASHBOARD                         |
|  - 6 Interactive Analyst Screens: Workspace, Evidence Explorer, Graph Canvas, |
|    Finding Inspector, ATT&CK Coverage, and Report & Evaluation                |
+-------------------------------------------------------------------------------+
```

---

## 5. Graph Ontology & Core Data Model

### Node Types
| Node Type | Description | Key Attributes |
| :--- | :--- | :--- |
| **`Asset`** | Target hosts, identities, applications, databases, cloud resources | `id`, `name`, `asset_type`, `criticality`, `ip_addresses`, `attributes` |
| **`Observation`** | Directly verified empirical event from a security sensor | `id`, `source_id`, `timestamp`, `category`, `raw_payload`, `provenance_hash` |
| **`AttackStep`** | Proposed or hypothesized action in a potential attack chain | `id`, `title`, `stage`, `status`, `is_inferred`, `prerequisites` |
| **`Technique`** | Formal MITRE ATT&CK reference from the Enterprise knowledge base | `technique_id`, `name`, `tactics`, `platforms`, `version` |
| **`SecurityControl`** | Defensive mechanism that limits, detects, or blocks an action | `id`, `name`, `category`, `state` (`confirmed_present`, `recommended`) |
| **`Finding`** | Analytical conclusion or conflict emitted by deterministic rules | `id`, `rule_id`, `severity` (`ERROR`, `WARNING`, `INFO`), `explanation` |

### Edge Types & Formal Semantics
| Edge Type | Source $\rightarrow$ Target | Semantic Meaning |
| :--- | :--- | :--- |
| **`PRECEDES`** | `Observation` $\rightarrow$ `Observation`<br>`AttackStep` $\rightarrow$ `AttackStep` | Event $A$ occurred at or before event $B$. **No causation implied.** |
| **`ENABLES`** | `AttackStep` $\rightarrow$ `AttackStep`<br>`Observation` $\rightarrow$ `AttackStep` | State or action $A$ satisfied necessary preconditions for $B$. |
| **`DEPENDS_ON`**| `AttackStep` $\rightarrow$ `Asset`<br>`AttackStep` $\rightarrow$ `AttackStep` | Action requires an underlying privilege, configuration, or asset. |
| **`OBSERVED_AS`**| `AttackStep` $\rightarrow$ `Observation` | Attack-step hypothesis is directly substantiated by evidence. |
| **`MAPPED_TO`** | `AttackStep` $\rightarrow$ `Technique`<br>`Observation` $\rightarrow$ `Technique` | Behavioral association with an ATT&CK technique with rationale. |
| **`MITIGATED_BY`**| `AttackStep` $\rightarrow$ `SecurityControl` | Defensive control capable of blocking or limiting the step. |
| **`CONTRADICTS`**| `Observation` $\rightarrow$ `AttackStep` | Verified evidence conflicts with a claim or expected condition. |

---

## 6. Deterministic Validation Rule Catalog (R100–R799)

Every rule executes as an isolated class implementing `BaseValidationRule` and emits structured `Finding` objects:

### Rule Families
- **Structural Invariants (`R100–R199`)**:
  - `R101` (`DanglingEdgeRule` - `ERROR`): Asserts that all edges connect existing registered nodes.
  - `R102` (`TypeCompatibilityRule` - `ERROR`): Enforces ontological type validity between source and target nodes.
  - `R103` (`CausalCycleRule` - `ERROR`): Asserts that causal `ENABLES` edges form a Directed Acyclic Graph (DAG).
- **Temporal Consistency (`R200–R299`)**:
  - `R201` (`ChronologicalOrderRule` - `ERROR`): Enforces $T(\text{Prerequisite}) \le T(\text{Action})$. A causal prerequisite cannot occur after the step it enables.
  - `R202` (`TemporalOrderWithoutCausalityRule` - `INFO`): Flags events sequenced via `PRECEDES` without proven causality (`ENABLES`).
- **Prerequisite Validation (`R300–R399`)**:
  - `R301` (`PrerequisiteDependencyRule` - `WARNING`): Verifies that declared step prerequisites link to valid enabling conditions.
- **Identity Consistency (`R400–R499`)**:
  - `R401` (`IdentityConflationRule` - `WARNING`): Flags transitions between disparate user accounts without credential-handoff or privilege-escalation evidence.
- **Contradiction Analysis (`R500–R599`)**:
  - `R501` (`ContradictionDetectionRule` - `ERROR`): Identifies and reports explicit `CONTRADICTS` relationships where verified observations refute hypothesized claims.
- **Evidence Coverage & Uncertainty (`R600–R699`)**:
  - `R601` (`UnsupportedHypothesisRule` - `INFO`): Flags attack steps marked as hypothesized that lack any direct `OBSERVED_AS` link.
- **Defensive Controls (`R700–R799`)**:
  - `R701` (`UnmitigatedHighRiskStepRule` - `WARNING`): Flags high-risk attack stages (credential dumping, lateral movement, exfiltration) lacking defensive controls.
  - `R702` (`BypassedControlRule` - `WARNING`): Detects when an attack step occurred despite a confirmed preventive security control documented in the environment.

---

## 7. Alternative Attack Paths & Uncertainty Model

Instead of arbitrary heuristic scores, paths are categorized into **four deterministic qualitative states**:

```
[Candidate Attack Path]
          │
          ├── Verified observation actively conflicts with a critical step?
          │     └─► CONTRADICTED
          │
          ├── All required transitions backed by direct empirical observations?
          │     └─► SUPPORTED
          │
          ├── Some transitions supported, but intermediate links rely on unverified assumptions?
          │     └─► PARTIALLY SUPPORTED
          │
          └── Essential transitions completely lack supporting observations?
                └─► UNSUBSTANTIATED
```

### Alternative Path Assessments
For every candidate path, the engine generates:
1. **Supporting Observations**: Direct log evidence references.
2. **Required Assumptions**: Inferred conditions operating without log trace.
3. **Missing Evidence**: What specific sensor telemetry would confirm or refute this path.
4. **Discriminator Telemetry**: Specific logs that differentiate competing hypotheses (e.g., Compromised Account vs. Legitimate Administrator Batch Job).

---

## 8. MITRE ATT&CK® Knowledge Base & Mapper

- **STIX 2.1 Reference Dataset**: Versioned enterprise matrix (`data/mitre/enterprise_attack_subset.json`).
- **Rule-Based Mapping Engine**: Matches observed activity and steps to candidate techniques (e.g., `T1110` for Brute Force, `T1003.001` for LSASS memory dumps, `T1059.001` for PowerShell execution, `T1021.001` for RDP lateral movement, `T1530` for cloud storage access).
- **Mapping Records**: Every mapping includes:
  - Candidate technique ID and name.
  - Mapping rationale explaining the behavioral match.
  - Supporting evidence references.
  - Required missing evidence to substantiate the technique.
  - Human review decision workflow (`requires_review`, `accepted`, `rejected`).

---

## 9. Durable Database Architecture & Alembic Migrations

The platform implements the Repository Pattern backed by SQLAlchemy 2.0 ORM with dual-engine support:
- **Production**: PostgreSQL 16 (configured via `DATABASE_URL`).
- **Local Dev**: Zero-configuration SQLite fallback (`attackpath.db`).

### Schema Overview (11 Relational Tables)
1. `projects`: Workspace tenants and ownership.
2. `attack_scenarios`: Incident scenario definitions and objectives.
3. `assets`: Entity registry (hosts, identities, databases, cloud).
4. `evidence_sources`: Source files, provenance, SHA-256 hashes, ingestion timestamps.
5. `observations`: Normalized empirical security events.
6. `graph_nodes`: Persisted graph nodes with composite primary key `(id, scenario_id)`.
7. `graph_edges`: Persisted directed edges with composite primary key `(id, scenario_id)`.
8. `validation_findings`: Structured outputs from rule execution.
9. `control_mappings`: Defensive controls linked to attack steps.
10. `analysis_runs`: Audit records of reasoning engine executions.
11. `review_decisions`: Human validation, reviewer rationale, and review tracking.

---

## 10. Versioned REST API Specification (FastAPI v1)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | System health check and version metadata |
| `POST` | `/api/v1/scenarios` | Create an investigation workspace |
| `GET` | `/api/v1/scenarios` | List all registered scenarios |
| `GET` | `/api/v1/scenarios/{id}` | Retrieve scenario metadata |
| `POST` | `/api/v1/scenarios/{id}/evidence` | Ingest evidence (JSON bundle or CSV event log) |
| `POST` | `/api/v1/scenarios/{id}/analyze` | Execute graph construction, rules, and path reasoning |
| `GET` | `/api/v1/scenarios/{id}/graph` | Retrieve graph nodes and edges for visualization |
| `GET` | `/api/v1/scenarios/{id}/findings` | Retrieve validation findings (`ERROR`, `WARNING`, `INFO`) |
| `GET` | `/api/v1/scenarios/{id}/paths` | Retrieve bounded, validated candidate attack paths |
| `GET` | `/api/v1/techniques` | Search indexed MITRE ATT&CK reference data |
| `POST` | `/api/v1/findings/{id}/review` | Record human analyst authorization/review decision |
| `GET` | `/api/v1/scenarios/{id}/export` | Export standalone interactive HTML report or JSON package |

---

## 11. Next.js 14 + React Flow Frontend (6 Analyst Screens)

The web application located in `apps/web` provides 6 main screens:

1. **Screen 01 — Scenario Workspace**:
   Create an investigation, configure scope, inspect active controls, and paste/upload JSON bundles.
2. **Screen 02 — Evidence Explorer**:
   Search and filter empirical observations by asset, actor identity, category, and timestamp. Inspect SHA-256 provenance hashes.
3. **Screen 03 — Directed Attack Graph (React Flow)**:
   Interactive canvas with color-coded nodes and edges. Click any node to inspect raw properties and evidence links.
4. **Screen 04 — Finding Details**:
   Rule-level inspector surfacing findings from R100–R799 with severity badges, affected entities, and remediation guidance.
5. **Screen 05 — MITRE ATT&CK Coverage**:
   Review candidate technique mappings, inspect mapping rationale, and approve or reject mappings with one click.
6. **Screen 06 — Report & Evaluation**:
   Export machine-readable JSON packages, open standalone HTML reports, and evaluate candidate path explanations.

---

## 12. Evaluation Benchmark Suite (30 Ground-Truth Scenarios)

The benchmark evaluates the reasoning engine against 30 versioned scenarios across 6 archetypes:
1. **Golden Path (`BENCH-GP-01` to `05`)**: Fully evidenced multi-stage attack chains. Expected: `SUPPORTED`.
2. **Contradiction Cases (`BENCH-CT-06` to `10`)**: Evidence refuting attacker claims (e.g. MFA push denied). Expected: `CONTRADICTED`, Rule `R501`.
3. **Prerequisite & Temporal Violations (`BENCH-PV-11` to `15`)**: Reversed timelines or missing prerequisites. Expected: `UNSUBSTANTIATED`, Rule `R201`.
4. **Telemetry Gaps (`BENCH-TG-16` to `20`)**: Unobserved intermediate links. Expected: `PARTIALLY_SUPPORTED`, Rule `R601`.
5. **Ambiguous Admin Activity (`BENCH-AA-21` to `25`)**: Routine IT admin scripts mimicking attacks. Expected: Rule `R202`.
6. **Control Bypass Cases (`BENCH-CB-26` to `30`)**: Attack steps occurring despite active defensive controls. Expected: Rule `R702`.

### Measured Benchmark Results
```text
======================================================================
 ATTACKPATH INTELLIGENCE — BENCHMARK EVALUATION SUITE v1.0.0
======================================================================
 Total Scenarios Evaluated: 30 / 30
 Passed Scenarios:          30 / 30 (100.0%)
 Mean Latency per Scenario: 0.77 ms

 KEY EVALUATION METRICS:
  * Edge Precision:              87.50%
  * Edge Recall:                 100.00%
  * Path Validity Rate:          60.00%
  * Unsupported-Claim Rate (UCR): 0.00%  (Target: 0.0% — ZERO unsupported assertions)
  * Contradiction Detection:     100.00% (Target: 100.0% — All injected conflicts detected)
  * ATT&CK Mapping Precision:    77.78%
  * Evidence Traceability:       100.00% (100% of material findings trace to evidence)
======================================================================
```

---

## 13. Installation & Quickstart Guide

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Local Setup
```bash
# Install Python dependencies
pip install -e .

# Run database migrations
python -m alembic upgrade head

# Install Frontend dependencies
cd apps/web
npm install
cd ../..
```

### 2. Launching the Backend API
```bash
python -m uvicorn services.api.main:app --port 8000
```
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health check: [http://localhost:8000/health](http://localhost:8000/health)

### 3. Launching the Web Dashboard
```bash
cd apps/web
npm run dev
```
- Open browser at: **[http://localhost:3000](http://localhost:3000)** (or `http://localhost:3001` if 3000 is occupied).

### 4. Running with Docker Compose
```bash
docker compose up --build
```

---

## 14. Testing & Verification

### Run the Full Pytest Suite (13/13 Passing)
```bash
python -m pytest -v
```

### Run the 30-Scenario Benchmark Evaluator
```bash
python scripts/run_benchmark.py
```

### Run the End-to-End Incident Demo
```bash
python scripts/demo_run.py
```

### Run the Live System Verification Script
```bash
python scripts/verify_live_system.py
```

---

## 15. Repository Structure

```text
attackpath-intelligence/
├── pyproject.toml              # Build & dependency specifications
├── docker-compose.yml          # Container configuration (Web + API + DB)
├── Dockerfile                  # API service container definition
├── alembic.ini                 # Database migration configuration
├── README.md                   # Complete system documentation
├── apps/
│   └── web/                    # Next.js 14 + React Flow Web Dashboard
│       ├── package.json
│       ├── tsconfig.json
│       ├── next.config.js
│       ├── Dockerfile
│       └── src/
│           ├── app/            # Layout and Home page
│           ├── components/     # The 6 interactive analyst screens
│           └── types/          # Domain TypeScript interfaces
├── packages/
│   ├── schemas/                # Core Pydantic v2 domain schemas
│   ├── graph_engine/           # NetworkX MultiDiGraph reasoning engine
│   ├── validators/             # Deterministic validation rules (R100–R799)
│   ├── attack_mapper/          # STIX 2.1 loader & rule-based technique matcher
│   ├── evidence/               # Parsers, normalizers & SHA-256 provenance
│   ├── database/               # SQLAlchemy 2.0 ORM models & repository
│   ├── reporting/              # Standalone interactive HTML report generator
│   └── benchmark/              # 30-scenario benchmark models & runner
├── services/
│   └── api/                    # Production FastAPI application
├── data/
│   ├── mitre/                  # Versioned ATT&CK dataset (v15.1)
│   └── benchmark/              # Versioned scorecard outputs
├── migrations/                 # Alembic migration scripts
├── reports/                    # Generated interactive HTML reports & JSON exports
├── scripts/
│   ├── demo_run.py             # Incident reasoning walkthrough
│   ├── run_benchmark.py        # Benchmark CLI evaluation runner
│   └── verify_live_system.py   # Live full-stack integration test
└── tests/
    ├── unit/                   # Graph, validator, database, and API unit tests
    └── benchmark/              # Benchmark regression tests
```

---

## 16. License

Licensed under the Apache License, Version 2.0.
