import pytest
from tests.integration.experience.test_storage import table_snapshot

from soc_agent.improvement_promotion import (
    ImprovementPromotionStore,
    migrate_improvement_promotion,
    schema,
)
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import StorageError, UnsupportedSchemaError


def test_v13_migration_preservation_rollback_and_future_rejection(review_case, monkeypatch):
    database = review_case.store.database
    before = table_snapshot(database)
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + (schema.STATEMENTS[0],))
        with pytest.raises(StorageError):
            migrate_improvement_promotion(database)
    assert table_snapshot(database) == before
    with database.transaction(write=False) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 13
    migrate_improvement_promotion(database)
    migrate_improvement_promotion(database)
    after = table_snapshot(database)
    for table in before:
        assert after[table] == before[table]
    with database.transaction(write=False) as conn:
        incident = conn.execute("SELECT incident_id FROM human_confirmations LIMIT 1").fetchone()[0]
    for command, params in (
        ("DELETE FROM incidents WHERE incident_id=?", (incident,)),
        ("UPDATE incidents SET incident_id=? WHERE incident_id=?", ("nonexisting", incident)),
        ("UPDATE incidents SET incident_id=? WHERE incident_id=?", (None, incident)),
    ):
        with pytest.raises(StorageError) as error:
            with database.transaction() as conn:
                conn.execute(command, params)
        assert "cannot be orphaned" in str(error.value.__cause__)
    from soc_agent.improvement_promotion.models import FAMILY_SCOPE

    # No NULL/missing-purpose loophole for a non-incident scope.
    with pytest.raises(StorageError):
        with database.transaction() as conn:
            conn.execute(
                "INSERT INTO human_confirmations VALUES (?,?,?,?,?,?)",
                ("test", "missing-purpose", str(FAMILY_SCOPE), 0, "{}", "0" * 64),
            )
    assert ImprovementPromotionStore(review_case.store).get_active_artifact() is None
    with database.transaction() as conn:
        conn.execute("PRAGMA user_version=15")
    with pytest.raises(UnsupportedSchemaError):
        GovernanceDatabase(database.path)
