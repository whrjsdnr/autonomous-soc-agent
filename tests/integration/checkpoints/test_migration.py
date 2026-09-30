import sqlite3

import pytest

from soc_agent.execution.durable import ExecutionStore, migrate
from soc_agent.investigation.runtime.persistence import CheckpointStore, migrate_checkpoints
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.confirmations import (
    SQLiteConfirmationConsumer,
    migrate_confirmations,
)
from soc_agent.review.persistence.models import StorageError, UnsupportedSchemaError
from tests.unit.confirmations.test_consumption import issue, verify


def rows(path):
    with sqlite3.connect(path) as connection:
        names = [
            r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        ]
        return {
            name: connection.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall()
            for name in names
        }


def test_migration_preserves_all_prior_governance_ledgers(prepared, durable, boundary, planning):
    executions, intent, _, _ = durable
    token, context = issue(boundary, planning)
    verify(boundary.authority, token, context)
    database = executions.database
    before = rows(database.path)
    migrate_checkpoints(database)
    after = rows(database.path)
    assert set(after) - set(before) == {"workflow_checkpoints", "workflow_trace"}
    for name in before:
        assert after[name] == before[name]
    migrate_checkpoints(database)
    migrate_confirmations(database)
    migrate(database)
    reopened = SQLiteGovernanceStore(database.path)
    assert CheckpointStore(reopened)
    assert ExecutionStore(reopened).load(intent.intent.execution_intent_id) == intent
    proof = boundary.provider.confirmations[token]
    assert (
        SQLiteConfirmationConsumer(reopened.database)
        .load(proof.provider_id, proof.confirmation_id)
        .consumed
    )


def test_migration_rolls_back_partial_ddl(runtime_case):
    c = runtime_case()
    migrate_confirmations(c.store.database)
    with sqlite3.connect(c.store.database.path) as connection:
        connection.execute("CREATE TABLE workflow_trace (existing TEXT)")
    before = rows(c.store.database.path)
    with pytest.raises(StorageError):
        migrate_checkpoints(c.store.database)
    assert rows(c.store.database.path) == before
    with sqlite3.connect(c.store.database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_explicit_version_chain_and_future_rejection(runtime_case):
    c = runtime_case()
    with pytest.raises(UnsupportedSchemaError):
        migrate_checkpoints(c.store.database)
    migrate_confirmations(c.store.database)
    migrate_checkpoints(c.store.database)
    with sqlite3.connect(c.store.database.path) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(UnsupportedSchemaError):
        SQLiteGovernanceStore(c.store.database.path)
    with sqlite3.connect(c.store.database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 99
