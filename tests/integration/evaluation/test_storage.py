import multiprocessing
import sqlite3

import pytest

from soc_agent.evaluation import EvaluationStore, ExperienceEvaluator, migrate_evaluations, schema
from soc_agent.experience import ExperienceStore, migrate_experiences
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import (
    CommitOutcomeUnknown,
    StorageError,
    UnsupportedSchemaError,
)
from tests.integration.experience.test_capture import capture_service
from tests.integration.experience.test_storage import table_snapshot
from tests.unit.investigation_runtime.conftest import decision_ready

from .test_evaluation import evaluator


def evaluate_in_process(path, identity, barrier, queue):
    store = EvaluationStore(ExperienceStore(SQLiteGovernanceStore(path)))
    barrier.wait(timeout=20)
    result = ExperienceEvaluator(store).evaluate(identity)
    queue.put(result.model_dump_json())


@pytest.mark.asyncio
async def test_independent_process_canonical_evaluation(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    experience = capture_service(case).capture(case.incident_id)
    service = evaluator(case)
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=evaluate_in_process,
            args=(
                case.store.database.path,
                experience.experience_id,
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
    assert len(service.store.list_for_incident(case.incident_id)) == 1


@pytest.mark.asyncio
async def test_migration_preserves_existing_data_and_rolls_back(runtime_case, monkeypatch):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    experience = capture_service(case).capture(case.incident_id)
    before = table_snapshot(case.store.database)
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_evaluations(case.store.database)
    assert table_snapshot(case.store.database) == before
    with case.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
    migrate_evaluations(case.store.database)
    migrate_evaluations(case.store.database)
    after = table_snapshot(case.store.database)
    assert all(after[key] == rows for key, rows in before.items())
    assert ExperienceStore(case.store).get(experience.experience_id) == experience
    migrate_experiences(case.store.database)  # older migration remains a no-op
    assert ExperienceEvaluator(EvaluationStore(ExperienceStore(case.store))).evaluate(
        experience.experience_id
    )


def test_fresh_chain_and_unsupported_future(tmp_path):
    from soc_agent.execution.durable.schema import migrate
    from soc_agent.investigation.runtime.persistence import migrate_checkpoints
    from soc_agent.review.persistence.confirmations import migrate_confirmations

    store = SQLiteGovernanceStore.create(tmp_path / "fresh.sqlite")
    with pytest.raises(UnsupportedSchemaError):
        migrate_evaluations(store.database)
    migrate(store.database)
    migrate_confirmations(store.database)
    migrate_checkpoints(store.database)
    migrate_experiences(store.database)
    migrate_evaluations(store.database)
    assert EvaluationStore(ExperienceStore(store)).get_for_experience("0" * 64) is None
    with sqlite3.connect(store.database.path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        SQLiteGovernanceStore(store.database.path)


@pytest.mark.asyncio
@pytest.mark.parametrize("lost", [False, True])
async def test_commit_failure_never_runs_external_work(runtime_case, monkeypatch, lost):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    experience = capture_service(case).capture(case.incident_id)
    service = evaluator(case)
    original = case.store.database._commit

    def fail(connection):
        if connection.execute("SELECT count(*) FROM evaluations").fetchone()[0]:
            if lost:
                original(connection)
            raise sqlite3.OperationalError("Injected")
        original(connection)

    with monkeypatch.context() as patch:
        patch.setattr(case.store.database, "_commit", fail)
        with pytest.raises(CommitOutcomeUnknown if lost else StorageError):
            service.evaluate(experience.experience_id)
    saved = service.store.get_for_experience(experience.experience_id)
    assert (saved is not None) is lost
    result = service.evaluate(experience.experience_id)
    assert service.store.list_for_incident(case.incident_id) == (result,)
    assert case.mocks["inspect_logs"].call_count == 0
