import multiprocessing
import sqlite3
from uuid import UUID

import pytest

from soc_agent.experience import (
    ExperienceCaptureService,
    ExperienceStore,
    migrate_experiences,
    schema,
)
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import (
    CommitOutcomeUnknown,
    StorageError,
    UnsupportedSchemaError,
)
from tests.unit.investigation_runtime.conftest import decision_ready, promoted_ready

from .test_capture import capture_service, finish


def capture_in_process(path, incident, barrier, queue):
    try:
        store = ExperienceStore(SQLiteGovernanceStore(path))
        capture = ExperienceCaptureService(store)
        barrier.wait(timeout=20)
        record = capture.capture(UUID(incident))
        queue.put(("ok", record.model_dump_json()))
    except Exception as error:
        queue.put(("error", type(error).__name__))
        raise


@pytest.mark.asyncio
async def test_independent_process_race_and_restart(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    service = capture_service(case)
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=capture_in_process,
            args=(case.store.database.path, str(case.incident_id), barrier, queue),
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
    assert results[0][0] == "ok"
    records = service.store.list_for_incident(case.incident_id)
    assert len(records) == 1
    assert records[0].model_dump_json() == results[0][1]


def table_snapshot(database):
    with database.transaction(write=False) as connection:
        names = [
            r[0]
            for r in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        return {
            name: tuple(
                tuple(row)
                for row in connection.execute(
                    'SELECT * FROM "' + name.replace('"', '""') + '" ORDER BY rowid'
                )
            )
            for name in names
        }


@pytest.mark.asyncio
async def test_migration_preserves_all_existing_tables(runtime_case):
    case = runtime_case(durable_workflow=True, severities=("high",))
    await promoted_ready(case, write=True)
    await finish(case)
    from soc_agent.review import HumanAction, SeverityChange
    from soc_agent.review.authentication import HumanActionContext
    from soc_agent.review.authorization import HumanRole
    from soc_agent.review.persistence import ledger
    from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
    from tests.review_support import authorize
    from tests.unit.confirmations.conftest import authority_for
    from tests.unit.identity.conftest import Boundary

    with case.store.database.transaction(write=False) as connection:
        review = ledger.get(
            connection, "reviews", str(case.runtime._workflows[case.incident_id].review.review_id)
        )
    request = case.reviews.propose_change(
        review,
        changes=(SeverityChange(before="info", after="medium"),),
        reason="Test request",
    )
    auth = authorize(case.reviews, case.authority, request, review)
    boundary = Boundary()
    boundary.authority = authority_for(boundary, SQLiteConfirmationConsumer(case.store.database))
    context = HumanActionContext(
        incident_id=case.incident_id,
        decision_id=review.target.decision_id,
        action=HumanAction.RECORD_REVIEW,
        binding_digest="b" * 64,
    )
    token = boundary.issue(context, (HumanRole.ADMIN,))
    boundary.authority.verify(
        credential=token, action=context.action, binding_digest=context.binding_digest
    )
    before = table_snapshot(case.store.database)
    assert before["reviews"] and before["execution_events"]
    assert before["authorizations"] and before["human_confirmations"]
    migrate_experiences(case.store.database)
    migrate_experiences(case.store.database)
    after = table_snapshot(case.store.database)
    assert {key: after[key] for key in before} == before
    assert after["experiences"] == ()
    # Existing migration chain remains a no-op on the explicitly upgraded DB.
    from soc_agent.execution.durable.schema import migrate
    from soc_agent.investigation.runtime.persistence import migrate_checkpoints
    from soc_agent.review.persistence.confirmations import migrate_confirmations

    migrate(case.store.database)
    migrate_confirmations(case.store.database)
    migrate_checkpoints(case.store.database)
    captured = ExperienceCaptureService(ExperienceStore(case.store)).capture(case.incident_id)
    assert any(
        r.kind == "state_authorization" and r.identity == auth.authorization_id
        for r in captured.content.references
    )


def test_migration_rollback_and_future_version(runtime_case, monkeypatch):
    case = runtime_case(durable_workflow=True)
    before = table_snapshot(case.store.database)
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_experiences(case.store.database)
    assert table_snapshot(case.store.database) == before
    with sqlite3.connect(case.store.database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        SQLiteGovernanceStore(case.store.database.path)


@pytest.mark.asyncio
@pytest.mark.parametrize("lost_response", [False, True])
async def test_capture_commit_failure_never_repeats_execution(
    runtime_case, monkeypatch, lost_response
):
    case = runtime_case(durable_workflow=True)
    await promoted_ready(case)
    await finish(case)
    capture = capture_service(case)
    calls = case.mocks["inspect_logs"].call_count
    before = case.store.load(case.incident_id)
    original = case.store.database._commit

    def fail(connection):
        if lost_response:
            original(connection)
        raise sqlite3.OperationalError("Injected commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(case.store.database, "_commit", fail)
        with pytest.raises(CommitOutcomeUnknown if lost_response else StorageError):
            capture.capture(case.incident_id)
    records = capture.store.list_for_incident(case.incident_id)
    assert len(records) == (1 if lost_response else 0)
    value = capture.capture(case.incident_id)
    assert capture.store.list_for_incident(case.incident_id) == (value,)
    assert case.mocks["inspect_logs"].call_count == calls
    assert case.store.load(case.incident_id) == before


def test_fresh_database_requires_explicit_migration_chain(tmp_path):
    from soc_agent.execution.durable.schema import migrate
    from soc_agent.investigation.runtime.persistence import migrate_checkpoints
    from soc_agent.review.persistence.confirmations import migrate_confirmations

    store = SQLiteGovernanceStore.create(tmp_path / "fresh.sqlite")
    with pytest.raises(UnsupportedSchemaError):
        migrate_experiences(store.database)
    migrate(store.database)
    migrate_confirmations(store.database)
    migrate_checkpoints(store.database)
    migrate_experiences(store.database)
    assert ExperienceStore(store).list_for_incident(UUID(int=0)) == ()
