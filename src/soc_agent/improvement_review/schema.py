"""Explicit additive v12 -> v13 human improvement review migration."""

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import UnsupportedSchemaError

STATEMENTS = (
    "CREATE TABLE improvement_review_requests (id TEXT PRIMARY KEY, "
    "candidate_id TEXT NOT NULL REFERENCES improvement_candidates(candidate_id), "
    "comparison_id TEXT NOT NULL REFERENCES offline_comparisons(id), "
    "payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE TABLE improvement_review_records (id TEXT PRIMARY KEY, "
    "request_id TEXT NOT NULL UNIQUE REFERENCES improvement_review_requests(id), "
    "candidate_id TEXT NOT NULL REFERENCES improvement_candidates(candidate_id), "
    "payload TEXT NOT NULL, digest TEXT NOT NULL)",
    "CREATE INDEX improvement_requests_candidate ON improvement_review_requests(candidate_id,id)",
    "CREATE INDEX improvement_records_candidate ON improvement_review_records(candidate_id,id)",
)


def migrate_improvement_review(database: GovernanceDatabase) -> None:
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (13, 14):
            connection.execute("SELECT id FROM improvement_review_requests LIMIT 0")
            connection.execute("SELECT id FROM improvement_review_records LIMIT 0")
            return
        if version != 12:
            raise UnsupportedSchemaError("Improvement review migration requires schema v12")
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=13")
