import copy
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from soc_agent.ingestion import EventIngestor, SOCEvent, migrate_ingestion
from soc_agent.ingestion.authentication import authentication_records
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import StorageError, UnsupportedSchemaError
from soc_agent.security_ai.authentication.aggregation import AuthenticationWindowExtractor
from tests.integration.api.conftest import call
from tests.integration.demo.conftest import ingest


def _ingest_worker(path, payload):
    store = SQLiteGovernanceStore(Path(path))
    return EventIngestor(store).ingest(SOCEvent.model_validate(payload)).model_dump(mode="json")


@pytest.mark.asyncio
async def test_provenance_features_and_no_automatic_evidence_or_severity(demo, event):
    result = await ingest(demo, event)
    state = demo.store.load(demo.incident_id).state
    assert state.severity == "info" and state.status == "new"
    assert not state.evidence and not state.observations
    receipt = demo.service.ingestion.load(demo.incident_id)
    assert receipt.canonical_digest == result["canonical_digest"]
    assert receipt.event.source == event["source"] and receipt.event.severity_hint == "critical"
    records = authentication_records(receipt)
    assert records == authentication_records(receipt)
    assert all(r.source_evidence_id is None and r.incident_id == demo.incident_id for r in records)
    windows = AuthenticationWindowExtractor().extract(records, state=state)
    assert windows[0].features.input_payload()["failed_login_count"] == 40


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["unknown", "secret", "time", "subject", "duplicate", "type"])
async def test_malformed_and_unknown_fields(demo, event, mutation):
    value = copy.deepcopy(event)
    if mutation == "unknown":
        value["approved"] = True
    elif mutation == "secret":
        value["attributes"]["token"] = "reject-this-field"
    elif mutation == "time":
        value["occurred_at"] = "not-a-timestamp"
    elif mutation == "subject":
        value["subject"] = "another-account"
    elif mutation == "duplicate":
        value["attributes"]["attempts"].append(value["attributes"]["attempts"][0])
    else:
        value["event_type"] = "compromise_confirmed"
    assert (await call(demo.app, "POST", "/events", value, demo.token))[0] == 422
    with demo.store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_replay_conflict_and_restart(demo, event):
    first = await ingest(demo, event)
    assert not first["duplicate"]
    again = await ingest(demo, event)
    assert again["duplicate"] and first["incident_id"] == again["incident_id"]
    conflict = {**event, "resource": "different-resource"}
    assert (await call(demo.app, "POST", "/events", conflict, demo.token))[0] == 409
    reopened = EventIngestor(SQLiteGovernanceStore(demo.store.database.path))
    assert reopened.ingest(SOCEvent.model_validate(event)).duplicate
    with demo.store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1


def test_independent_process_duplicate_ingest(demo, event):
    with ProcessPoolExecutor(
        max_workers=2, mp_context=multiprocessing.get_context("spawn")
    ) as pool:
        jobs = [pool.submit(_ingest_worker, str(demo.store.database.path), event) for _ in range(2)]
        results = [job.result(timeout=30) for job in jobs]
    assert sorted(r["duplicate"] for r in results) == [False, True]
    assert len({r["incident_id"] for r in results}) == 1


def test_event_insert_failure_rolls_back_incident(demo, event):
    with demo.store.database.transaction() as connection:
        connection.execute("""CREATE TRIGGER reject_event BEFORE INSERT ON soc_events
            BEGIN SELECT RAISE(ABORT,'test failure'); END""")
    with pytest.raises(StorageError):
        demo.service.ingestion.ingest(SOCEvent.model_validate(event))
    with demo.store.database.transaction(write=False) as connection:
        for table in ("incidents", "snapshots", "soc_events"):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_extension_version_rejected_without_reset(demo):
    with demo.store.database.transaction() as connection:
        connection.execute("UPDATE soc_ingestion_schema SET version=999")
    with pytest.raises(UnsupportedSchemaError):
        migrate_ingestion(demo.store)
    with demo.store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT version FROM soc_ingestion_schema").fetchone()[0] == 999


def test_synthetic_fixtures_are_explicit():
    root = Path(__file__).parents[3] / "examples/authentication"
    for name in ("benign", "suspicious", "duplicate", "conflict"):
        assert SOCEvent.model_validate_json((root / f"{name}.json").read_text()).synthetic
    assert json.loads((root / "duplicate.json").read_text()) == json.loads(
        (root / "suspicious.json").read_text()
    )
