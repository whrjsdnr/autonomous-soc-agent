import json
import sqlite3

import pytest

from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.investigation.runtime.persistence.models import StaleCheckpoint, WorkflowInFlight
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import CommitOutcomeUnknown, StorageError, StoredDataError
from tests.unit.investigation_runtime.conftest import decision_ready

from .conftest import restart


@pytest.mark.asyncio
async def test_stale_writer_does_not_start_step(runtime_case):
    c = runtime_case(durable_workflow=True)
    old = restart(c)
    c.runtime.restore(c.incident_id)
    await old.advance(c.incident_id)
    with pytest.raises(StaleCheckpoint):
        await c.runtime.advance(c.incident_id)
    assert c.llm.calls == 0 and c.mocks["inspect_logs"].call_count == 0


@pytest.mark.asyncio
async def test_trace_insert_failure_rolls_back_publication_and_keeps_claim(runtime_case):
    c = runtime_case(durable_workflow=True)
    before, trace = CheckpointStore(c.store).load(c.incident_id)
    with sqlite3.connect(c.store.database.path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_trace BEFORE INSERT ON workflow_trace "
            "BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
    with pytest.raises(StorageError):
        await c.runtime.advance(c.incident_id)
    with sqlite3.connect(c.store.database.path) as connection:
        row = connection.execute("SELECT revision,claim FROM workflow_checkpoints").fetchone()
        assert row[0] == before.revision and row[1] is not None
        assert connection.execute("SELECT count(*) FROM workflow_trace").fetchone()[0] == len(
            trace.entries
        )
    restart(c)
    with pytest.raises(WorkflowInFlight):
        c.runtime.restore(c.incident_id)
    assert c.mocks["inspect_logs"].call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["claim", "publish"])
async def test_commit_response_loss_never_repeats_a_step(runtime_case, monkeypatch, boundary):
    c = runtime_case(durable_workflow=True)
    database = c.runtime._checkpoints.database
    original = database._commit
    lost = False

    def commit(connection):
        nonlocal lost
        row = connection.execute("SELECT revision,claim FROM workflow_checkpoints").fetchone()
        matches = row[1] is not None if boundary == "claim" else row[0] == 1
        original(connection)
        if matches and not lost:
            lost = True
            raise OSError("Lost commit response")

    monkeypatch.setattr(database, "_commit", commit)
    with pytest.raises(CommitOutcomeUnknown):
        await c.runtime.advance(c.incident_id)
    with pytest.raises(WorkflowInFlight):
        await c.runtime.advance(c.incident_id)
    restart(c)
    if boundary == "claim":
        with pytest.raises(WorkflowInFlight):
            c.runtime.restore(c.incident_id)
    else:
        assert c.runtime.restore(c.incident_id).next_step == "route"
        assert len(c.runtime.trace(c.incident_id).entries) == 2
    assert c.mocks["inspect_logs"].call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["digest", "artifact", "trace", "run", "cursor"])
async def test_corruption_and_stale_artifact_fail_closed(runtime_case, mutation):
    c = runtime_case(durable_workflow=True)
    await decision_ready(c)
    with sqlite3.connect(c.store.database.path) as connection:
        if mutation == "trace":
            connection.execute("DELETE FROM workflow_trace WHERE sequence=2")
        elif mutation == "run":
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("UPDATE workflow_checkpoints SET run_id='other-run'")
        elif mutation == "digest":
            connection.execute("UPDATE workflow_checkpoints SET digest='bad'")
        else:
            payload = json.loads(
                connection.execute("SELECT payload FROM workflow_checkpoints").fetchone()[0]
            )
            if mutation == "artifact":
                payload["artifacts"]["assessment"]["threat_assessment"]["summary"] = "substituted"
            else:
                payload["result"]["next_step"] = "act"
            # Even with matching JSON digest, domain/reference validation must still run.
            import hashlib

            from soc_agent._json import canonical_json_object

            data = canonical_json_object(payload)
            connection.execute(
                "UPDATE workflow_checkpoints SET payload=?,digest=?",
                (data, hashlib.sha256(data.encode()).hexdigest()),
            )
    restart(c)
    with pytest.raises((ValueError, StoredDataError)):
        c.runtime.restore(c.incident_id)
    assert c.llm.calls == 1


@pytest.mark.asyncio
async def test_checkpoint_does_not_contain_tool_approval_or_confirmation(runtime_case):
    from tests.unit.investigation_runtime.conftest import promoted_ready

    c = runtime_case(durable_workflow=True, severities=("high",))
    await promoted_ready(c, write=True)
    checkpoint, _ = CheckpointStore(c.store).load(c.incident_id)
    payload = ledger.serialize(checkpoint)
    assert checkpoint.approval_id is not None
    for forbidden in ('"credential"', '"confirmation"', '"approved_by"', '"approved_at"'):
        assert forbidden not in payload
    assert '"approval_id"' in payload
