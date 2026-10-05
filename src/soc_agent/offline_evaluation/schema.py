"""Explicit additive v9 -> v10 migration, preserving prior historical artifacts."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    """CREATE TABLE offline_evaluation_specifications (
        specification_id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL REFERENCES improvement_candidates(candidate_id),
        payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    "CREATE INDEX offline_specifications_candidate "
    "ON offline_evaluation_specifications(candidate_id, specification_id)",
    """CREATE TABLE candidate_test_plans (
        plan_id TEXT PRIMARY KEY,
        specification_id TEXT NOT NULL
            REFERENCES offline_evaluation_specifications(specification_id),
        candidate_id TEXT NOT NULL REFERENCES improvement_candidates(candidate_id),
        payload TEXT NOT NULL, digest TEXT NOT NULL)""",
    "CREATE INDEX offline_plans_candidate ON candidate_test_plans(candidate_id, plan_id)",
)


def migrate_offline_evaluation(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 10:
            connection.execute(
                "SELECT specification_id FROM offline_evaluation_specifications LIMIT 0"
            )
            connection.execute("SELECT plan_id FROM candidate_test_plans LIMIT 0")
            return
        if version != 9:
            raise UnsupportedSchemaError("Offline evaluation migration requires schema v9")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=10")
