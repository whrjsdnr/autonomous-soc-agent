"""Explicit additive v5 -> v6; Experience and governance data remain intact."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    """CREATE TABLE evaluations (
        evaluation_id TEXT PRIMARY KEY,
        experience_id TEXT NOT NULL REFERENCES experiences(experience_id),
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
        evaluator_version TEXT NOT NULL,
        payload TEXT NOT NULL, digest TEXT NOT NULL,
        UNIQUE(experience_id, evaluator_version))""",
    "CREATE INDEX evaluations_incident ON evaluations(incident_id, evaluation_id)",
)


def migrate_evaluations(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (6, 7, 8, 9, 10, 11, 12):
            connection.execute("SELECT evaluation_id FROM evaluations LIMIT 0")
            return
        if version != 5:
            raise UnsupportedSchemaError("Evaluation migration requires schema v5")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=6")
