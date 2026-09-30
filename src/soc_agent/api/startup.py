"""Explicit local database startup; caller supplies all analysis/governance adapters."""

from pathlib import Path

from soc_agent.execution.durable import migrate
from soc_agent.investigation.runtime.persistence import CheckpointStore, migrate_checkpoints
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.confirmations import migrate_confirmations


def open_store(path: Path, *, create: bool = False) -> SQLiteGovernanceStore:
    store = SQLiteGovernanceStore.create(path) if create else SQLiteGovernanceStore(path)
    migrate(store.database)
    migrate_confirmations(store.database)
    migrate_checkpoints(store.database)
    CheckpointStore(store)
    return store
