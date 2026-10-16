"""Clock fixtures never adjust the OS clock or relax persisted UTC validation."""

from datetime import timedelta
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

import soc_agent.investigation.runtime.service as service
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.investigation.runtime.persistence.models import (
    CheckpointClockRollback,
    WorkflowCheckpoint,
    WorkflowInFlight,
)

from .conftest import restart


def test_original_progress_error_can_mean_clock_or_round_corruption(runtime_case):
    c = runtime_case(durable_workflow=True)
    saved, _ = CheckpointStore(c.store).load(c.incident_id)
    for changes in (
        {"updated_at": saved.created_at - timedelta(seconds=0.471)},
        {"rounds": saved.round_limit + 1},
    ):
        with pytest.raises(ValidationError, match="Invalid checkpoint progress metadata"):
            WorkflowCheckpoint.model_validate({**saved.model_dump(), **changes})


@pytest.mark.asyncio
async def test_store_rejects_successor_time_regression_above_creation(runtime_case, monkeypatch):
    c = runtime_case(durable_workflow=True)
    initial, _ = CheckpointStore(c.store).load(c.incident_id)
    monkeypatch.setattr(service, "utc_now", lambda: initial.created_at + timedelta(seconds=2))
    await c.runtime.advance(c.incident_id)
    store = CheckpointStore(c.store)
    expected, trace = store.load(c.incident_id)
    token = store.claim(expected)
    # Valid standalone schema, but an invalid successor to the committed revision.
    updated = WorkflowCheckpoint.model_validate(
        {
            **expected.model_dump(),
            "revision": expected.revision + 1,
            "updated_at": initial.created_at + timedelta(seconds=1),
        }
    )
    with pytest.raises(ValueError, match="CHECKPOINT_CLOCK_ROLLBACK"):
        store.publish(expected, token, updated, trace)
    with store.database.transaction(write=False) as connection:
        row = connection.execute("SELECT revision,claim FROM workflow_checkpoints").fetchone()
        assert row[0] == expected.revision and row[1] == str(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("delta", [0, 1])
async def test_equal_or_increasing_utc_preserves_revision_and_restart(
    runtime_case, monkeypatch, delta
):
    c = runtime_case(durable_workflow=True)
    before, _ = CheckpointStore(c.store).load(c.incident_id)
    stamp = before.updated_at + timedelta(seconds=delta)
    monkeypatch.setattr(service, "utc_now", lambda: stamp)
    await c.runtime.advance(c.incident_id)
    after, trace = CheckpointStore(c.store).load(c.incident_id)
    assert after.updated_at == stamp and after.created_at == before.created_at
    assert after.revision == before.revision + 1
    restart(c)
    assert c.runtime.restore(c.incident_id) == after.result
    assert c.runtime.trace(c.incident_id) == trace


@pytest.mark.asyncio
async def test_rollback_before_claim_does_no_work_and_requires_fresh_runtime(
    runtime_case, monkeypatch
):
    c = runtime_case(durable_workflow=True)
    store = CheckpointStore(c.store)
    before, trace = store.load(c.incident_id)
    stamp = before.updated_at - timedelta(seconds=0.471)
    monkeypatch.setattr(service, "utc_now", lambda: stamp)
    with pytest.raises(CheckpointClockRollback):
        await c.runtime.advance(c.incident_id)
    assert store.load(c.incident_id) == (before, trace)
    assert c.llm.calls == c.mocks["inspect_logs"].call_count == 0
    with pytest.raises(WorkflowInFlight):
        await c.runtime.advance(c.incident_id)
    restart(c)  # Explicit operator action, not automatic resume or retry.
    assert c.runtime.restore(c.incident_id) == before.result


@pytest.mark.asyncio
async def test_rollback_during_step_preserves_claim_and_blocks_restart(runtime_case, monkeypatch):
    c = runtime_case(durable_workflow=True)
    store = CheckpointStore(c.store)
    before, trace = store.load(c.incident_id)
    clock = Mock(side_effect=[before.updated_at, before.updated_at - timedelta(seconds=0.471)])
    monkeypatch.setattr(service, "utc_now", clock)
    with pytest.raises(CheckpointClockRollback):
        await c.runtime.advance(c.incident_id)
    assert clock.call_count == 2
    with store.database.transaction(write=False) as connection:
        row = connection.execute("SELECT revision,claim FROM workflow_checkpoints").fetchone()
        assert row[0] == before.revision and row[1] is not None
        assert connection.execute("SELECT count(*) FROM workflow_trace").fetchone()[0] == len(
            trace.entries
        )
    restart(c)
    with pytest.raises(WorkflowInFlight):
        c.runtime.restore(c.incident_id)


@pytest.mark.asyncio
async def test_runtime_detects_rollback_even_above_creation(runtime_case, monkeypatch):
    c = runtime_case(durable_workflow=True)
    before, _ = CheckpointStore(c.store).load(c.incident_id)
    monkeypatch.setattr(service, "utc_now", lambda: before.created_at + timedelta(seconds=2))
    await c.runtime.advance(c.incident_id)
    committed, _ = CheckpointStore(c.store).load(c.incident_id)
    monkeypatch.setattr(service, "utc_now", lambda: before.created_at + timedelta(seconds=1))
    with pytest.raises(CheckpointClockRollback):
        await c.runtime.advance(c.incident_id)
    assert CheckpointStore(c.store).load(c.incident_id)[0] == committed
