"""Explicit v4 -> v5 additive migration; no source records are changed."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    """CREATE TABLE experiences (
        experience_id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
        run_id TEXT NOT NULL REFERENCES workflow_checkpoints(run_id),
        payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    "CREATE INDEX experiences_incident ON experiences(incident_id, experience_id)",
)


def migrate_experiences(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 5:
            connection.execute("SELECT experience_id FROM experiences LIMIT 0")
            return
        if version != 4:
            raise UnsupportedSchemaError("Experience migration requires schema v4")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=5")
