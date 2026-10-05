"""Explicit additive v8 -> v9 migration; prior records remain unchanged."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    """CREATE TABLE failure_patterns (
        pattern_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL REFERENCES improvement_datasets(dataset_id),
        payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    "CREATE INDEX failure_patterns_dataset ON failure_patterns(dataset_id, pattern_id)",
    """CREATE TABLE improvement_candidates (
        candidate_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL REFERENCES improvement_datasets(dataset_id),
        pattern_id TEXT NOT NULL REFERENCES failure_patterns(pattern_id),
        candidate_type TEXT NOT NULL,
        payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    "CREATE INDEX improvement_candidates_dataset "
    "ON improvement_candidates(dataset_id, candidate_id)",
)


def migrate_candidates(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (9, 10):
            connection.execute("SELECT pattern_id FROM failure_patterns LIMIT 0")
            connection.execute("SELECT candidate_id FROM improvement_candidates LIMIT 0")
            return
        if version != 8:
            raise UnsupportedSchemaError("Candidate migration requires schema v8")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=9")
