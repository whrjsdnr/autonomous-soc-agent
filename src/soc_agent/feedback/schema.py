"""Explicit additive v6 -> v7 migration; no replacement of existing data."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    """CREATE TABLE analyst_feedback (
        feedback_id TEXT PRIMARY KEY,
        submission_id TEXT NOT NULL,
        provider_id TEXT NOT NULL, subject_id TEXT NOT NULL, session_id TEXT NOT NULL,
        incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
        experience_id TEXT NOT NULL REFERENCES experiences(experience_id),
        evaluation_id TEXT NOT NULL REFERENCES evaluations(evaluation_id),
        payload TEXT NOT NULL, digest TEXT NOT NULL,
        UNIQUE(provider_id, subject_id, submission_id))""",
    """CREATE TABLE feedback_audit (
        feedback_id TEXT PRIMARY KEY REFERENCES analyst_feedback(feedback_id),
        payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    "CREATE INDEX feedback_evaluation ON analyst_feedback(evaluation_id, feedback_id)",
    "CREATE INDEX feedback_experience ON analyst_feedback(experience_id, feedback_id)",
    "CREATE INDEX feedback_incident ON analyst_feedback(incident_id, feedback_id)",
)


def migrate_feedback(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (7, 8, 9, 10):
            connection.execute("SELECT feedback_id FROM analyst_feedback LIMIT 0")
            connection.execute("SELECT feedback_id FROM feedback_audit LIMIT 0")
            return
        if version != 6:
            raise UnsupportedSchemaError("Feedback migration requires schema v6")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=7")
