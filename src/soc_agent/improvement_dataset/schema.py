"""Explicit additive v7 -> v8 migration."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    """CREATE TABLE improvement_samples (
        sample_id TEXT PRIMARY KEY,
        evaluation_id TEXT NOT NULL REFERENCES evaluations(evaluation_id),
        payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    """CREATE TABLE improvement_datasets (
        dataset_id TEXT PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    """CREATE TABLE dataset_sample_membership (
        dataset_id TEXT NOT NULL REFERENCES improvement_datasets(dataset_id),
        sample_id TEXT NOT NULL REFERENCES improvement_samples(sample_id),
        position INTEGER NOT NULL CHECK(position >= 0),
        PRIMARY KEY(dataset_id, sample_id), UNIQUE(dataset_id, position))""",
)


def migrate_datasets(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (8, 9, 10):
            for table in (
                "improvement_samples",
                "improvement_datasets",
                "dataset_sample_membership",
            ):
                connection.execute(f"SELECT * FROM {table} LIMIT 0")
            return
        if version != 7:
            raise UnsupportedSchemaError("Dataset migration requires schema v7")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=8")
