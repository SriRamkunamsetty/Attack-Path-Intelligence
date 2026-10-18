"""Unit tests for database persistence and repository pattern."""

from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from packages.database.models import Base, ScenarioModel, ObservationModel
from packages.database.repository import AttackPathRepository
from packages.schemas.models import (
    Asset,
    AssetType,
    AttackStep,
    Observation,
    ReviewStatus,
    Scenario,
    ScenarioBundle,
)


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_repository_save_and_retrieve_scenario(db_session):
    repo = AttackPathRepository(db_session)
    scen = Scenario(
        id="scen-db-01",
        name="Durable Database Test Scenario",
        description="Testing persistence in SQLite / PostgreSQL",
        objective="Verify ORM mappings",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    repo.create_or_update_scenario(scen)

    retrieved = repo.get_scenario("scen-db-01")
    assert retrieved is not None
    assert retrieved.name == "Durable Database Test Scenario"
    assert retrieved.id == "scen-db-01"


def test_repository_save_bundle(db_session):
    repo = AttackPathRepository(db_session)
    scen = Scenario(
        id="scen-db-02",
        name="Bundle Test Scenario",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    obs = Observation(
        id="obs-db-1",
        source_id="edr",
        timestamp=datetime.now(timezone.utc),
        category="endpoint",
        description="LSASS memory handle opened by suspicious process",
    )
    bundle = ScenarioBundle(
        scenario=scen,
        assets=[Asset(id="h1", name="Host-01", asset_type=AssetType.HOST)],
        observations=[obs],
        hypotheses=[AttackStep(id="s1", title="Credential Access")],
    )
    repo.save_bundle(bundle)

    db_obs = db_session.query(ObservationModel).filter(ObservationModel.id == "obs-db-1").first()
    assert db_obs is not None
    assert db_obs.category == "endpoint"
    assert db_obs.scenario_id == "scen-db-02"


def test_repository_record_review(db_session):
    repo = AttackPathRepository(db_session)
    review = repo.record_review(
        finding_id="R501-test",
        reviewer="senior_analyst_alice",
        decision=ReviewStatus.ACCEPTED,
        rationale="Confirmed valid contradiction with firewall drop logs.",
    )
    assert review.finding_id == "R501-test"
    assert review.decision == "accepted"
    assert review.reviewer == "senior_analyst_alice"
