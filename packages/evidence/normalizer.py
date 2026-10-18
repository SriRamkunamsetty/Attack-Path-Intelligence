"""Evidence ingestion, normalization, and provenance tracking."""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from packages.schemas.models import (
    Asset,
    AssetType,
    AttackStep,
    ControlState,
    EvidenceSource,
    GraphEdge,
    Observation,
    Scenario,
    ScenarioBundle,
    SecurityControl,
)


class EvidenceNormalizer:
    """Parses, normalizes, and validates heterogeneous security evidence."""

    @staticmethod
    def compute_sha256(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @classmethod
    def from_json_bundle(cls, file_content: str, source_name: str = "json_bundle") -> ScenarioBundle:
        file_hash = cls.compute_sha256(file_content)
        data = json.loads(file_content)

        scen_data = data.get("scenario", {})
        scenario = Scenario(
            id=scen_data.get("id", "scen-default"),
            name=scen_data.get("name", "Imported Incident Scenario"),
            description=scen_data.get("description", ""),
            objective=scen_data.get("objective", ""),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            evidence_source_ids=[source_name],
        )

        assets: List[Asset] = []
        for a in data.get("assets", []):
            assets.append(Asset(**a))

        observations: List[Observation] = []
        for o in data.get("observations", []):
            if isinstance(o.get("timestamp"), str):
                ts = datetime.fromisoformat(o["timestamp"].replace("Z", "+00:00"))
            else:
                ts = datetime.now(timezone.utc)
            flags = []
            if not o.get("asset_id"):
                flags.append("Missing affected asset_id")
            if not o.get("actor_identity"):
                flags.append("Unattributed actor identity")

            observations.append(
                Observation(
                    id=o["id"],
                    source_id=source_name,
                    timestamp=ts,
                    category=o.get("category", "generic"),
                    description=o.get("description", ""),
                    asset_id=o.get("asset_id"),
                    actor_identity=o.get("actor_identity"),
                    target_identity=o.get("target_identity"),
                    raw_payload=o.get("raw_payload", {}),
                    provenance_hash=file_hash,
                    data_quality_flags=flags,
                )
            )

        hypotheses: List[AttackStep] = []
        for h in data.get("hypotheses", []):
            hypotheses.append(AttackStep(**h))

        controls: List[SecurityControl] = []
        for c in data.get("controls", []):
            controls.append(SecurityControl(**c))

        edges: List[GraphEdge] = []
        for e in data.get("explicit_edges", []):
            edges.append(GraphEdge(**e))

        return ScenarioBundle(
            scenario=scenario,
            assets=assets,
            observations=observations,
            hypotheses=hypotheses,
            controls=controls,
            explicit_edges=edges,
        )

    @classmethod
    def from_csv_logs(
        cls,
        csv_content: str,
        source_name: str = "csv_log",
        scenario_id: str = "scen-csv",
    ) -> List[Observation]:
        file_hash = cls.compute_sha256(csv_content)
        reader = csv.DictReader(io.StringIO(csv_content))
        observations: List[Observation] = []

        for idx, row in enumerate(reader):
            obs_id = row.get("id") or f"obs-csv-{idx + 1}"
            raw_ts = row.get("timestamp")
            if raw_ts:
                try:
                    ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            desc = row.get("description") or row.get("message") or f"Event {obs_id}"
            cat = row.get("category") or row.get("event_type") or "endpoint"
            asset_id = row.get("asset_id") or row.get("host")
            actor = row.get("actor_identity") or row.get("user")

            observations.append(
                Observation(
                    id=obs_id,
                    source_id=source_name,
                    timestamp=ts,
                    category=cat,
                    description=desc,
                    asset_id=asset_id,
                    actor_identity=actor,
                    raw_payload=dict(row),
                    provenance_hash=file_hash,
                )
            )

        return observations
