import sqlite3

import pytest
from tests.unit.durable_execution.test_lifecycle import expire

from soc_agent.execution.durable import ExecutionStore, Lifecycle
from soc_agent.execution.durable.errors import ExecutionOutcomeUnknown
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import CommitOutcomeUnknown, StorageError


@pytest.mark.parametrize("point", ["intent", "claim", "boundary", "side_effect", "tool_failure"])
def test_crash_windows_reopen(durable, monkeypatch, point):
    store, record, _, _ = durable
    identity = record.intent.execution_intent_id
    if point != "intent":
        claim = store.claim(identity, claimant="dead-worker")
        if point != "claim":
            store.transition(claim, Lifecycle.EXECUTING)
    # Process-crash versions with actual Tool calls live in integration/process tests.
    reopened = ExecutionStore(SQLiteGovernanceStore(store.database.path))
    expire(monkeypatch)
    reopened.recover()
    expected = Lifecycle.PENDING if point in ("intent", "claim") else Lifecycle.UNCERTAIN
    assert reopened.load(identity).state == expected


@pytest.mark.parametrize("operation", ["record_update", "audit_insert"])
def test_atomic_audit_rollback(durable, operation):
    store, record, _, _ = durable
    with sqlite3.connect(store.database.path) as connection:
        table = "execution_records" if operation == "record_update" else "execution_events"
        verb = "UPDATE" if operation == "record_update" else "INSERT"
        connection.execute(
            f"CREATE TRIGGER reject_write BEFORE {verb} ON {table} "
            "BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(StorageError):
        store.claim(record.intent.execution_intent_id, claimant="worker")
    assert store.load(record.intent.execution_intent_id) == record
    assert len(store.events(record.intent.execution_intent_id)) == 1


@pytest.mark.parametrize("committed", [False, True])
def test_claim_commit_failure_or_response_lost(durable, monkeypatch, committed):
    store, record, _, _ = durable

    def broken(connection):
        if committed:
            connection.commit()
        raise sqlite3.OperationalError("injected")

    monkeypatch.setattr(store.database, "_commit", broken)
    with pytest.raises(CommitOutcomeUnknown if committed else StorageError):
        store.claim(record.intent.execution_intent_id, claimant="worker")
    reopened = ExecutionStore(SQLiteGovernanceStore(store.database.path))
    assert reopened.load(record.intent.execution_intent_id).state == (
        Lifecycle.CLAIMED if committed else Lifecycle.PENDING
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("committed", [False, True])
async def test_outcome_commit_failure_no_retry(durable, monkeypatch, committed):
    store, record, executor, _ = durable
    original = store.database._commit

    def fail_success(connection):
        row = connection.execute("SELECT state FROM execution_records").fetchone()
        if row and row[0] == "succeeded":
            if committed:
                connection.commit()
            raise sqlite3.OperationalError("injected outcome failure")
        original(connection)

    monkeypatch.setattr(store.database, "_commit", fail_success)
    with pytest.raises(ExecutionOutcomeUnknown):
        await executor.execute(record.intent.execution_intent_id, claimant="worker")
    reopened = ExecutionStore(SQLiteGovernanceStore(store.database.path))
    expire(monkeypatch)
    reopened.recover()
    assert reopened.load(record.intent.execution_intent_id).state == (
        Lifecycle.SUCCEEDED if committed else Lifecycle.UNCERTAIN
    )


@pytest.mark.asyncio
async def test_timeout_is_uncertain(durable, monkeypatch):
    store, record, executor, _ = durable

    async def timeout(*args, **kwargs):
        raise TimeoutError("remote outcome unknown")

    monkeypatch.setattr("soc_agent.tools.base.Tool.execute", timeout)
    with pytest.raises(TimeoutError):
        await executor.execute(record.intent.execution_intent_id, claimant="worker")
    assert store.load(record.intent.execution_intent_id).state == Lifecycle.UNCERTAIN


@pytest.mark.asyncio
async def test_reported_tool_failure_persisted(durable, monkeypatch):
    from soc_agent.tools.errors import ToolExecutionError

    store, record, executor, _ = durable

    async def failed(*args, **kwargs):
        raise ToolExecutionError("adapter reported failure")

    monkeypatch.setattr("soc_agent.tools.base.Tool.execute", failed)
    with pytest.raises(ToolExecutionError):
        await executor.execute(record.intent.execution_intent_id, claimant="worker")
    result = store.load(record.intent.execution_intent_id)
    assert result.state == Lifecycle.FAILED
    assert result.invocation_started_at is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("committed", [False, True])
async def test_invocation_commit_failure_never_calls_tool(durable, monkeypatch, committed):
    store, record, executor, _ = durable
    original = store.database._commit

    def broken(connection):
        row = connection.execute("SELECT state FROM execution_records").fetchone()
        if row and row[0] == "executing":
            if committed:
                connection.commit()
            raise sqlite3.OperationalError("boundary commit error")
        original(connection)

    async def forbidden(*args, **kwargs):
        pytest.fail("Invocation must wait for confirmed boundary commit")

    monkeypatch.setattr(store.database, "_commit", broken)
    monkeypatch.setattr("soc_agent.tools.base.Tool.execute", forbidden)
    with pytest.raises(CommitOutcomeUnknown if committed else StorageError):
        await executor.execute(record.intent.execution_intent_id, claimant="worker")
    reopened = ExecutionStore(SQLiteGovernanceStore(store.database.path))
    expire(monkeypatch)
    reopened.recover()
    assert reopened.load(record.intent.execution_intent_id).state == (
        Lifecycle.UNCERTAIN if committed else Lifecycle.PENDING
    )
