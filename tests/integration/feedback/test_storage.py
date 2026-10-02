import multiprocessing
import sqlite3

import pytest

from soc_agent.evaluation import EvaluationStore
from soc_agent.experience import ExperienceStore
from soc_agent.feedback import AnalystFeedbackService, FeedbackStore, migrate_feedback, schema
from soc_agent.review.authorization import RBACPermissionVerifier
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import (
    CommitOutcomeUnknown,
    StorageError,
    UnsupportedSchemaError,
)
from tests.integration.evaluation.test_evaluation import evaluator
from tests.integration.experience.test_capture import capture_service
from tests.integration.experience.test_storage import table_snapshot
from tests.unit.investigation_runtime.conftest import decision_ready

from .conftest import issue


def submit_in_process(path, request, boundary, credential, barrier, queue):
    store = FeedbackStore(EvaluationStore(ExperienceStore(SQLiteGovernanceStore(path))))
    service = AnalystFeedbackService(
        store,
        provider=boundary[0],
        provider_id="test-identity",
        permissions=RBACPermissionVerifier(roles=boundary[1]),
    )
    barrier.wait(timeout=20)
    result = service.submit(request, credential=credential)
    queue.put(result.model_dump_json())


def test_independent_process_canonical_submission(feedback_case):
    c = feedback_case
    credential = issue(c)
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=submit_in_process,
            args=(
                c.store.database.path,
                c.request,
                (c.boundary.provider, c.boundary.roles),
                credential,
                barrier,
                queue,
            ),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    results = [queue.get(timeout=40) for _ in processes]
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    assert results[0] == results[1]
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT count(*) FROM analyst_feedback").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM feedback_audit").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM human_confirmations").fetchone()[0] == 1


@pytest.mark.parametrize("lost", [False, True])
def test_confirmation_feedback_audit_atomic_commit(feedback_case, monkeypatch, lost):
    c = feedback_case
    credential = issue(c)
    original = c.store.database._commit

    def fail(connection):
        if connection.execute("SELECT count(*) FROM analyst_feedback").fetchone()[0]:
            if lost:
                original(connection)
            raise sqlite3.OperationalError("Injected lost response or failed commit")
        original(connection)

    with monkeypatch.context() as patch:
        patch.setattr(c.store.database, "_commit", fail)
        with pytest.raises(CommitOutcomeUnknown if lost else StorageError):
            c.feedback.submit(c.request, credential=credential)
    with c.store.database.transaction(write=False) as connection:
        for table in ("human_confirmations", "analyst_feedback", "feedback_audit"):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == int(lost)
    # Durable query distinguishes actual commit; no blind replay on uncertain commit.
    if lost:
        result = c.feedback.submit(c.request, credential=credential)
        assert c.feedback_store.list_for_incident(c.incident_id) == (result,)
    else:
        # Provider may have consumed confirmation even when SQLite rolled back. New confirmation.
        assert c.feedback.submit(c.request, credential=issue(c))


@pytest.mark.asyncio
async def test_v6_migration_preserves_data_and_rolls_back(runtime_case, monkeypatch):
    c = runtime_case(durable_workflow=True)
    await decision_ready(c)
    experience = capture_service(c).capture(c.incident_id)
    evaluation = evaluator(c).evaluate(experience.experience_id)
    before = table_snapshot(c.store.database)
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_feedback(c.store.database)
    assert table_snapshot(c.store.database) == before
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 6
    migrate_feedback(c.store.database)
    migrate_feedback(c.store.database)
    after = table_snapshot(c.store.database)
    assert all(after[name] == rows for name, rows in before.items())
    store = EvaluationStore(ExperienceStore(c.store))
    assert store.get(evaluation.evaluation_id) == evaluation
    assert store.experiences.get(experience.experience_id) == experience


def test_fresh_chain_future_rejected(tmp_path):
    from soc_agent.evaluation import migrate_evaluations
    from soc_agent.execution.durable.schema import migrate
    from soc_agent.experience import migrate_experiences
    from soc_agent.investigation.runtime.persistence import migrate_checkpoints
    from soc_agent.review.persistence.confirmations import migrate_confirmations

    store = SQLiteGovernanceStore.create(tmp_path / "fresh.sqlite")
    with pytest.raises(UnsupportedSchemaError):
        migrate_feedback(store.database)
    migrate(store.database)
    migrate_confirmations(store.database)
    migrate_checkpoints(store.database)
    migrate_experiences(store.database)
    migrate_evaluations(store.database)
    migrate_feedback(store.database)
    for migration in (
        migrate,
        migrate_confirmations,
        migrate_checkpoints,
        migrate_experiences,
        migrate_evaluations,
        migrate_feedback,
    ):
        migration(store.database)
    assert FeedbackStore(EvaluationStore(ExperienceStore(store)))
    with sqlite3.connect(store.database.path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        SQLiteGovernanceStore(store.database.path)
