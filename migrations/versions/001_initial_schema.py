"""Initial schema migration for AttackPath Intelligence.

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-18

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Projects
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("owner", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. Attack Scenarios
    op.create_table(
        "attack_scenarios",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("project_id", sa.String(length=64), sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("objective", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. Assets
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), sa.ForeignKey("attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=False),
        sa.Column("criticality", sa.String(length=32), nullable=False),
        sa.Column("ip_addresses", sa.JSON(), nullable=True),
        sa.Column("identities", sa.JSON(), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=True),
    )

    # 4. Evidence Sources
    op.create_table(
        "evidence_sources",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), sa.ForeignKey("attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("file_hash", sa.String(length=64), nullable=False, index=True),
        sa.Column("ingestion_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False, default=0),
    )

    # 5. Observations
    op.create_table(
        "observations",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), sa.ForeignKey("attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("source_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("category", sa.String(length=64), nullable=False, index=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("asset_id", sa.String(length=64), nullable=True),
        sa.Column("actor_identity", sa.String(length=128), nullable=True, index=True),
        sa.Column("target_identity", sa.String(length=128), nullable=True),
        sa.Column("raw_payload", sa.JSON(), nullable=True),
        sa.Column("provenance_hash", sa.String(length=64), nullable=True),
        sa.Column("data_quality_flags", sa.JSON(), nullable=True),
    )

    # 6. Graph Nodes
    op.create_table(
        "graph_nodes",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), sa.ForeignKey("attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("node_type", sa.String(length=64), nullable=False, index=True),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("data", sa.JSON(), nullable=True),
    )

    # 7. Graph Edges
    op.create_table(
        "graph_edges",
        sa.Column("id", sa.String(length=255), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), sa.ForeignKey("attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("source", sa.String(length=128), nullable=False, index=True),
        sa.Column("target", sa.String(length=128), nullable=False, index=True),
        sa.Column("edge_type", sa.String(length=64), nullable=False, index=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=True),
        sa.Column("metadata_payload", sa.JSON(), nullable=True),
    )

    # 8. Validation Findings
    op.create_table(
        "validation_findings",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), sa.ForeignKey("attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("rule_id", sa.String(length=32), nullable=False, index=True),
        sa.Column("rule_name", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False, index=True),
        sa.Column("affected_node_ids", sa.JSON(), nullable=True),
        sa.Column("affected_edge_ids", sa.JSON(), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("remediation_guidance", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 9. Control Mappings
    op.create_table(
        "control_mappings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), sa.ForeignKey("attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("step_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=64), nullable=False),
        sa.Column("effectiveness_verified", sa.Boolean(), default=False),
        sa.Column("description", sa.Text(), nullable=True),
    )

    # 10. Analysis Runs
    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scenario_id", sa.String(length=64), sa.ForeignKey("attack_scenarios.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rule_engine_version", sa.String(length=32), nullable=False),
        sa.Column("dataset_version", sa.String(length=32), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=True),
        sa.Column("candidate_paths_json", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, default="completed"),
    )

    # 11. Review Decisions
    op.create_table(
        "review_decisions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("finding_id", sa.String(length=128), nullable=False, index=True),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reviewer", sa.String(length=128), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("review_decisions")
    op.drop_table("analysis_runs")
    op.drop_table("control_mappings")
    op.drop_table("validation_findings")
    op.drop_table("graph_edges")
    op.drop_table("graph_nodes")
    op.drop_table("observations")
    op.drop_table("evidence_sources")
    op.drop_table("assets")
    op.drop_table("attack_scenarios")
    op.drop_table("projects")
