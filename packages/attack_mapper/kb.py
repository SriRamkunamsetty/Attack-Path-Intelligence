"""MITRE ATT&CK Knowledge Base Loader and Indexer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional
from packages.schemas.models import Technique


class AttackKnowledgeBase:
    """Manages versioned MITRE ATT&CK techniques with search and metadata retrieval."""

    def __init__(self, dataset_path: Optional[str] = None) -> None:
        self.techniques: Dict[str, Technique] = {}
        self.by_name: Dict[str, Technique] = {}
        self.by_tactic: Dict[str, List[Technique]] = {}

        if dataset_path:
            self.load_from_json(dataset_path)
        else:
            default_path = Path(__file__).resolve().parents[2] / "data" / "mitre" / "enterprise_attack_subset.json"
            if default_path.exists():
                self.load_from_json(str(default_path))

    def load_from_json(self, filepath: str) -> None:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data:
            tech = Technique(**item)
            self.techniques[tech.technique_id] = tech
            self.by_name[tech.name.lower()] = tech
            for tactic in tech.tactics:
                self.by_tactic.setdefault(tactic.lower(), []).append(tech)

    def get_by_id(self, technique_id: str) -> Optional[Technique]:
        return self.techniques.get(technique_id)

    def search(
        self,
        query: str,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
        limit: int = 10,
    ) -> List[Technique]:
        q = query.lower()
        results: List[Technique] = []

        candidates = self.by_tactic.get(tactic.lower(), list(self.techniques.values())) if tactic else list(self.techniques.values())

        for tech in candidates:
            # Platform filter
            if platform and not any(p.lower() == platform.lower() for p in tech.platforms):
                continue

            # Query match
            if q in tech.technique_id.lower() or q in tech.name.lower() or q in tech.description.lower():
                results.append(tech)
                if len(results) >= limit:
                    break

        return results

    def list_all(self) -> List[Technique]:
        return list(self.techniques.values())
