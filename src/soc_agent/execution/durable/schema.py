"""Explicit additive governance v1 -> v2 migration; never reset existing data."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    """CREATE TABLE execution_records (
        id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
        promoted_id TEXT NOT NULL UNIQUE, approval_id TEXT UNIQUE,
        revision INTEGER NOT NULL CHECK(revision>=0), state TEXT NOT NULL,
        payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    """CREATE TABLE execution_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
        execution_id TEXT NOT NULL REFERENCES execution_records(id),
        revision INTEGER NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL,
        UNIQUE(execution_id, revision))""",
)


def migrate(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (2, 3, 4, 5, 6, 7):
            return
        if version != 1:
            raise UnsupportedSchemaError("Execution migration requires governance schema v1")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=2")
