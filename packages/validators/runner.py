"""Rule engine runner to orchestrate all validation checks."""

from __future__ import annotations

from typing import List, Optional
from packages.graph_engine.engine import AttackGraphEngine
from packages.schemas.models import Finding, Severity
from packages.validators.base import BaseValidationRule
from packages.validators.rules import (
    BypassedControlRule,
    CausalCycleRule,
    ChronologicalOrderRule,
    ContradictionDetectionRule,
    DanglingEdgeRule,
    IdentityConflationRule,
    PrerequisiteDependencyRule,
    TemporalOrderWithoutCausalityRule,
    TypeCompatibilityRule,
    UnmitigatedHighRiskStepRule,
    UnsupportedHypothesisRule,
)


class RuleEngineRunner:
    """Orchestrates deterministic validation rules against an AttackGraphEngine instance."""

    def __init__(self, rules: Optional[List[BaseValidationRule]] = None) -> None:
        self.rules: List[BaseValidationRule] = rules or [
            # Structural
            DanglingEdgeRule(),
            TypeCompatibilityRule(),
            CausalCycleRule(),
            # Temporal
            ChronologicalOrderRule(),
            TemporalOrderWithoutCausalityRule(),
            # Prerequisite
            PrerequisiteDependencyRule(),
            # Identity
            IdentityConflationRule(),
            # Contradiction
            ContradictionDetectionRule(),
            # Evidence Coverage
            UnsupportedHypothesisRule(),
            # Defensive
            UnmitigatedHighRiskStepRule(),
            BypassedControlRule(),
        ]

    def register_rule(self, rule: BaseValidationRule) -> None:
        self.rules.append(rule)

    def run(self, engine: AttackGraphEngine) -> List[Finding]:
        """Execute all rules and return list of findings."""
        all_findings: List[Finding] = []
        for rule in self.rules:
            try:
                findings = rule.evaluate(engine)
                all_findings.extend(findings)
            except Exception as exc:
                all_findings.append(
                    Finding(
                        id=f"ERR-{rule.rule_id}",
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        severity=Severity.ERROR,
                        explanation=f"Validator internal execution error: {str(exc)}",
                        remediation_guidance="Check validator inputs and graph consistency.",
                    )
                )
        return all_findings
