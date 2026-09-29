import sqlite3

import pytest

from soc_agent.execution.durable import ExecutionStore, migrate
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.review.persistence.confirmations import (
    SQLiteConfirmationConsumer,
    migrate_confirmations,
)
from soc_agent.review.persistence.models import StorageError, UnsupportedSchemaError


def test_migration_preserves_governance_and_execution(prepared, durable):
    state, _, _, governance, _, review, request, authorization = prepared
    executions, record, _, _ = durable
    before_state = governance.load(state.incident_id)
    before_events = governance.events()
    before_execution_events = executions.events(record.intent.execution_intent_id)
    migrate_confirmations(governance.database)
    migrate_confirmations(governance.database)
    migrate(governance.database)  # Earlier explicit migration remains safe on v3.
    reopened = SQLiteGovernanceStore(governance.database.path)
    restored = PersistentHumanReviewService(store=reopened)
    assert reopened.load(state.incident_id) == before_state
    assert review in restored.reviews()
    assert request in restored.requests()
    assert authorization in restored.authorizations()
    assert reopened.events() == before_events
    new_execution = ExecutionStore(reopened)
    assert new_execution.load(record.intent.execution_intent_id) == record
    assert new_execution.events(record.intent.execution_intent_id) == before_execution_events
    assert SQLiteConfirmationConsumer(reopened.database)


def test_migration_failure_preserves_v2(durable):
    executions, record, _, _ = durable
    database = executions.database
    with sqlite3.connect(database.path) as connection:
        connection.execute("CREATE TABLE human_confirmations (existing TEXT)")
    with pytest.raises(StorageError):
        migrate_confirmations(database)
    with sqlite3.connect(database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("SELECT existing FROM human_confirmations").fetchall() == []
    assert executions.load(record.intent.execution_intent_id) == record


def test_v1_requires_explicit_chain(planning):
    database = planning[3].database
    with pytest.raises(UnsupportedSchemaError):
        migrate_confirmations(database)
    with pytest.raises(UnsupportedSchemaError):
        SQLiteConfirmationConsumer(database)
    migrate(database)
    migrate_confirmations(database)
    assert SQLiteConfirmationConsumer(database)


def test_future_schema_rejected(boundary, planning):
    database = planning[3].database
    with sqlite3.connect(database.path) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(UnsupportedSchemaError):
        SQLiteGovernanceStore(database.path)
