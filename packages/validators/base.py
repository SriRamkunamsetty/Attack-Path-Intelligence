"""Base classes for deterministic graph validation rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List
from packages.graph_engine.engine import AttackGraphEngine
from packages.schemas.models import Finding, Severity


class BaseValidationRule(ABC):
    """Abstract base class for all deterministic graph validation rules."""

    rule_id: str
    rule_name: str
    default_severity: Severity
    description: str

    @abstractmethod
    def evaluate(self, engine: AttackGraphEngine) -> List[Finding]:
        """Inspect the graph and return any findings."""
        pass
