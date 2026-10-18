# Deterministic Validation Rules Catalog

The reasoning engine executes modular rule classes implementing `BaseValidationRule`. Every rule emits structured `Finding` objects containing:
- `rule_id`: Unique identifier (e.g., `R201`)
- `rule_name`: Semantic name
- `severity`: `ERROR`, `WARNING`, or `INFO`
- `affected_node_ids`: List of affected node IDs
- `affected_edge_ids`: List of affected edge IDs
- `evidence_refs`: Traceable observation references
- `explanation`: Human-readable technical reasoning
- `remediation_guidance`: Recommended defensive or investigative action

---

## Rule Families

### 1. Structural Invariants (R100–R199)
- **`R101` (`DanglingEdgeRule` - `ERROR`)**:
  Ensures every edge references existing registered source and target nodes in the graph.
- **`R102` (`TypeCompatibilityRule` - `ERROR`)**:
  Enforces ontological type validity (e.g., `OBSERVED_AS` must connect `AttackStep` and `Observation`; `MITIGATED_BY` must connect `AttackStep` and `SecurityControl`).
- **`R103` (`CausalCycleRule` - `ERROR`)**:
  Ensures causal `ENABLES` edges form a Directed Acyclic Graph (DAG). Attack steps cannot circularly enable themselves.

### 2. Temporal Consistency (R200–R299)
- **`R201` (`ChronologicalOrderRule` - `ERROR`)**:
  Enforces $T(\text{Prerequisite}) \le T(\text{Action})$. A condition occurring at $T_2$ cannot enable a step that occurred at $T_1$ if $T_1 < T_2$.
- **`R202` (`TemporalOrderWithoutCausalityRule` - `INFO`)**:
  Flags when events are chronologically ordered via `PRECEDES` without verified causal links (`ENABLES`), preventing false attribution of coincidental events.

### 3. Prerequisite Validation (R300–R399)
- **`R301` (`PrerequisiteDependencyRule` - `WARNING`)**:
  Verifies that declared step prerequisites are satisfied by incoming `ENABLES` or `DEPENDS_ON` edges.

### 4. Identity Consistency (R400–R499)
- **`R401` (`IdentityConflationRule` - `WARNING`)**:
  Flags causal transitions between disparate user accounts or session tokens without explicit credential-handoff or lateral-movement evidence.

### 5. Contradiction Analysis (R500–R599)
- **`R501` (`ContradictionDetectionRule` - `ERROR`)**:
  Surfaces explicit evidentiary conflicts where verified observations directly refute hypothesized steps (e.g., user explicitly rejected an MFA push challenge, disproving an unauthenticated bypass hypothesis).

### 6. Evidence Coverage & Uncertainty (R600–R699)
- **`R601` (`UnsupportedHypothesisRule` - `INFO`)**:
  Surfaces attack steps marked as hypothesized that lack any direct `OBSERVED_AS` link to an observation, making investigative blind spots transparent.

### 7. Defensive Controls (R700–R799)
- **`R701` (`UnmitigatedHighRiskStepRule` - `WARNING`)**:
  Flags high-risk attack stages (credential dumping, exfiltration, lateral movement) that lack any associated security control (`MITIGATED_BY`).
- **`R702` (`BypassedControlRule` - `WARNING`)**:
  Detects when an attack step was successfully observed despite an active security control documented as `CONFIRMED_PRESENT` in the environment.
