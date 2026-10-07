"""Explicit additive v13 -> v14 bounded version registry migration."""

from soc_agent.improvement_promotion.models import FAMILY_SCOPE
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    (
        "CREATE TABLE improvement_artifacts (id TEXT PRIMARY KEY, family TEXT NOT NULL, "
        "version INTEGER NOT NULL CHECK(version>0), payload_digest TEXT NOT NULL, "
        "payload TEXT NOT NULL, digest TEXT NOT NULL, UNIQUE(family,version), "
        "UNIQUE(family,payload_digest))"
    ),
    (
        "CREATE TABLE improvement_active_pointers (family TEXT PRIMARY KEY, artifact_id "
        "TEXT NOT NULL REFERENCES improvement_artifacts(id), version INTEGER NOT NULL, "
        "revision INTEGER NOT NULL CHECK(revision>0))"
    ),
    (
        "CREATE TABLE improvement_promotion_requests (id TEXT PRIMARY KEY, payload TEXT "
        "NOT NULL, digest TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE improvement_rollback_requests (id TEXT PRIMARY KEY, payload TEXT "
        "NOT NULL, digest TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE improvement_promotion_records (id TEXT PRIMARY KEY, request_id "
        "TEXT NOT NULL UNIQUE REFERENCES improvement_promotion_requests(id), payload "
        "TEXT NOT NULL, digest TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE improvement_rollback_records (id TEXT PRIMARY KEY, request_id "
        "TEXT NOT NULL UNIQUE REFERENCES improvement_rollback_requests(id), payload "
        "TEXT NOT NULL, digest TEXT NOT NULL)"
    ),
)


def migrate_improvement_promotion(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 14:
            for table in (
                "improvement_artifacts",
                "improvement_active_pointers",
                "improvement_promotion_requests",
                "improvement_rollback_requests",
                "improvement_promotion_records",
                "improvement_rollback_records",
            ):
                connection.execute(f"SELECT * FROM {table} LIMIT 0")
            return
        if version != 13:
            raise UnsupportedSchemaError("Improvement promotion migration requires v13")
        # Preserve exact receipts; activation uses a non-incident family resource.
        connection.execute(
            "CREATE TABLE confirmations_v14 (provider_id TEXT NOT NULL, "
            "confirmation_id TEXT NOT NULL, incident_id TEXT NOT NULL, consumed INTEGER NOT NULL "
            "CHECK(consumed IN (0,1)), payload TEXT NOT NULL, digest TEXT NOT NULL, "
            "PRIMARY KEY(provider_id,confirmation_id))"
        )
        connection.execute("INSERT INTO confirmations_v14 SELECT * FROM human_confirmations")
        connection.execute("DROP TABLE human_confirmations")
        connection.execute("ALTER TABLE confirmations_v14 RENAME TO human_confirmations")
        for operation in ("INSERT", "UPDATE"):
            connection.execute(
                f"CREATE TRIGGER confirmation_scope_{operation.lower()} "
                f"BEFORE {operation} ON human_confirmations WHEN "
                "NOT EXISTS(SELECT 1 FROM incidents WHERE incident_id=NEW.incident_id) "
                f"AND NOT (NEW.incident_id='{FAMILY_SCOPE}' AND "
                "COALESCE(json_extract(NEW.payload,'$.verification.context.action'),'') IN "
                "('improvement_artifact_promotion','improvement_artifact_rollback')) "
                "BEGIN SELECT RAISE(ABORT,'Invalid confirmation resource scope'); END"
            )
        # Retain the old FK's protection against orphaning an existing receipt.
        for event, condition, label in (
            ("DELETE", "", "delete"),
            ("UPDATE OF incident_id", "NEW.incident_id IS NOT OLD.incident_id AND ", "update"),
        ):
            connection.execute(
                f"CREATE TRIGGER confirmation_incident_{label} "
                f"BEFORE {event} ON incidents WHEN {condition}"
                "EXISTS(SELECT 1 FROM human_confirmations WHERE incident_id=OLD.incident_id) "
                "BEGIN SELECT RAISE(ABORT,'Confirmed incident resource cannot be orphaned'); END"
            )
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=14")
