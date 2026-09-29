from datetime import timedelta
from uuid import uuid4

import pytest

from soc_agent.execution.durable import Lifecycle
from soc_agent.execution.durable.errors import ClaimConflict
from soc_agent.review.errors import StaleSnapshotError
from soc_agent.state.evidence import utc_now


def expire(monkeypatch):
    monkeypatch.setattr(
        "soc_agent.execution.durable.store.utc_now", lambda: utc_now() + timedelta(hours=2)
    )


def test_claim_recovery_fences_old_owner(durable, monkeypatch):
    store, record, _, _ = durable
    identity = record.intent.execution_intent_id
    old = store.claim(identity, claimant="old")
    with pytest.raises(ClaimConflict):
        store.claim(identity, claimant="second")
    assert store.recover() == ()
    expire(monkeypatch)
    (recovered,) = store.recover()
    assert recovered.state == Lifecycle.PENDING
    new = store.claim(identity, claimant="new")
    with pytest.raises(ClaimConflict):
        store.transition(old, Lifecycle.EXECUTING)
    assert store.transition(new, Lifecycle.EXECUTING).state == Lifecycle.EXECUTING


@pytest.mark.parametrize("terminal", [Lifecycle.SUCCEEDED, Lifecycle.FAILED, Lifecycle.UNCERTAIN])
def test_terminal_never_reenters(durable, terminal):
    store, record, _, _ = durable
    claim = store.claim(record.intent.execution_intent_id, claimant="worker")
    running = store.transition(claim, Lifecycle.EXECUTING)
    final = store.transition(running, terminal, reason="Reported outcome")
    with pytest.raises(ClaimConflict):
        store.transition(final, Lifecycle.EXECUTING)
    with pytest.raises(ClaimConflict):
        store.claim(record.intent.execution_intent_id, claimant="worker")


def test_invocation_recovery_never_reclaims(durable, monkeypatch):
    store, record, _, _ = durable
    claim = store.claim(record.intent.execution_intent_id, claimant="worker")
    store.transition(claim, Lifecycle.EXECUTING)
    expire(monkeypatch)
    (recovered,) = store.recover()
    assert recovered.state == Lifecycle.UNCERTAIN
    with pytest.raises(ClaimConflict):
        store.claim(record.intent.execution_intent_id, claimant="worker")


@pytest.mark.asyncio
async def test_stale_state_failure_no_tool(durable, monkeypatch):
    store, record, executor, workflow = durable
    state = workflow[0][0]
    evidence = state.evidence[0].model_copy(update={"evidence_id": uuid4()})
    store.governance.append_evidence(record.intent.promoted.content.current_snapshot, evidence)

    async def forbidden(*args, **kwargs):
        pytest.fail("Tool must not run")

    monkeypatch.setattr("soc_agent.tools.base.Tool.execute", forbidden)
    with pytest.raises(StaleSnapshotError):
        await executor.execute(record.intent.execution_intent_id, claimant="worker")
    result = store.load(record.intent.execution_intent_id)
    assert result.state == Lifecycle.FAILED
    assert result.invocation_started_at is None
