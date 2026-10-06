"""Explicit additive v3 -> v4 migration, using the existing SQLite transaction boundary."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    """CREATE TABLE workflow_checkpoints (
        incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id),
        run_id TEXT NOT NULL UNIQUE, revision INTEGER NOT NULL CHECK(revision>=0),
        claim TEXT, payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    """CREATE TABLE workflow_trace (
        run_id TEXT NOT NULL REFERENCES workflow_checkpoints(run_id),
        sequence INTEGER NOT NULL CHECK(sequence>0), entry_id TEXT NOT NULL,
        payload TEXT NOT NULL, digest TEXT NOT NULL,
        PRIMARY KEY(run_id, sequence), UNIQUE(run_id, entry_id))""",
)


def migrate_checkpoints(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (4, 5, 6, 7, 8, 9, 10, 11, 12):
            return
        if version != 3:
            raise UnsupportedSchemaError("Checkpoint migration requires schema v3")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=4")
