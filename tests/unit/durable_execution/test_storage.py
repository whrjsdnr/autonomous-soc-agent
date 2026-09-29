import sqlite3

import pytest
from tests.unit.promotion.conftest import approve, promoted

from soc_agent.execution.durable import ExecutionStore, migrate
from soc_agent.execution.durable.errors import ClaimConflict
from soc_agent.execution.errors import ApprovalRequiredError
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError


def test_migration_preserves_governance(workflow):
    governance = workflow[0][3]
    before = governance.load(workflow[0][0].incident_id)
    events = governance.events()
    with pytest.raises(UnsupportedSchemaError):
        ExecutionStore(governance)
    migrate(governance.database)
    migrate(governance.database)
    assert governance.load(before.state.incident_id) == before
    assert governance.events() == events
    assert governance.applications() == ()
    assert ExecutionStore(governance)


def test_create_restart_and_stable_identity(durable):
    store, record, _, workflow = durable
    again = store.create(
        workflow[5], record.intent.promoted, approval_id=record.intent.binding.approval_id
    )
    assert again == record
    reopened = ExecutionStore(SQLiteGovernanceStore(store.database.path))
    assert reopened.load(record.intent.execution_intent_id) == record
    assert reopened.events(record.intent.execution_intent_id) == store.events(
        record.intent.execution_intent_id
    )


@pytest.mark.parametrize("field", ["payload", "digest", "state", "revision", "approval_id"])
def test_corruption_rejected(durable, field):
    store, record, _, _ = durable
    with sqlite3.connect(store.database.path) as connection:
        value = 999 if field == "revision" else "corrupt"
        connection.execute(f"UPDATE execution_records SET {field}=?", (value,))
    with pytest.raises(StoredDataError):
        store.load(record.intent.execution_intent_id)


def test_future_schema_rejected(durable):
    store, _, _, _ = durable
    with sqlite3.connect(store.database.path) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(UnsupportedSchemaError):
        SQLiteGovernanceStore(store.database.path)


def test_no_approval_no_intent(workflow):
    governance = workflow[0][3]
    migrate(governance.database)
    store = ExecutionStore(governance)
    value = promoted(workflow, "test_response")
    with pytest.raises(ApprovalRequiredError):
        store.create(workflow[5], value)
    assert governance.events()


def test_duplicate_promotion_with_new_approval_rejected(durable):
    store, record, _, workflow = durable
    approval = approve(workflow, record.intent.promoted)
    from soc_agent.execution.durable.errors import ExecutionReplay

    with pytest.raises(ExecutionReplay):
        store.create(workflow[5], record.intent.promoted, approval_id=approval.approval_id)


@pytest.mark.asyncio
async def test_success_restart_replay(durable):
    store, record, executor, _ = durable
    result = await executor.execute(record.intent.execution_intent_id, claimant="worker")
    assert result.tool_name == "test_response"
    reopened = ExecutionStore(SQLiteGovernanceStore(store.database.path))
    assert reopened.load(record.intent.execution_intent_id).state == "succeeded"
    with pytest.raises(ClaimConflict):
        reopened.claim(record.intent.execution_intent_id, claimant="new-worker")


def test_migration_preserves_review_authorization_and_audit(prepared):
    state, decision, _, governance, service, review, request, authorization = prepared
    before_state = governance.load(state.incident_id)
    before_events = governance.events()
    migrate(governance.database)
    reopened = SQLiteGovernanceStore(governance.database.path)
    from soc_agent.review.persistence import PersistentHumanReviewService

    restored = PersistentHumanReviewService(store=reopened)
    assert reopened.load(state.incident_id) == before_state
    assert restored.reviews() == (review,)
    assert restored.requests() == (request,)
    assert restored.authorizations() == (authorization,)
    assert reopened.events() == before_events
    assert not reopened.authorization_status(authorization.authorization_id).consumed
    assert ExecutionStore(reopened)


def test_migration_failure_rolls_back_no_reset(workflow):
    governance = workflow[0][3]
    before = governance.events()
    with sqlite3.connect(governance.database.path) as connection:
        connection.execute("CREATE TABLE execution_events (unrelated TEXT)")
    from soc_agent.review.persistence.models import StorageError

    with pytest.raises(StorageError):
        migrate(governance.database)
    with sqlite3.connect(governance.database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='execution_records'"
            ).fetchone()
            is None
        )
    assert governance.events() == before
