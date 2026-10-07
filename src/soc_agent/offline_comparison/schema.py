"""Explicit additive v10 -> v11 migration for offline-only artifacts."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = tuple(
    statement
    for table in (
        "offline_candidate_variants",
        "offline_evaluation_results",
        "offline_comparisons",
    )
    for statement in (
        f"CREATE TABLE {table} (id TEXT PRIMARY KEY, "
        "plan_id TEXT NOT NULL REFERENCES candidate_test_plans(plan_id), "
        "candidate_id TEXT NOT NULL REFERENCES improvement_candidates(candidate_id), "
        "payload TEXT NOT NULL, digest TEXT NOT NULL)",
        f"CREATE INDEX {table}_candidate ON {table}(candidate_id,id)",
    )
)


def migrate_offline_comparison(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (11, 12, 13, 14):
            for table in (
                "offline_candidate_variants",
                "offline_evaluation_results",
                "offline_comparisons",
            ):
                connection.execute(f"SELECT id FROM {table} LIMIT 0")
            return
        if version != 10:
            raise UnsupportedSchemaError("Offline comparison migration requires schema v10")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=11")


BASELINE_STATEMENTS = (
    "CREATE TABLE frozen_offline_baselines (baseline_id TEXT PRIMARY KEY, "
    "target_reference TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE INDEX frozen_baselines_target "
    "ON frozen_offline_baselines(target_reference,baseline_id)",
)


def migrate_frozen_baselines(database: GovernanceDatabase) -> None:
    """Explicit v11 -> v12: independent snapshots cannot use plan-bound v11 tables."""
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (12, 13, 14):
            connection.execute("SELECT baseline_id FROM frozen_offline_baselines LIMIT 0")
            return
        if version != 11:
            raise UnsupportedSchemaError("Frozen baseline migration requires schema v11")
        for statement in BASELINE_STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=12")
