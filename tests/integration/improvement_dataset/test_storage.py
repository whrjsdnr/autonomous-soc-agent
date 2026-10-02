import multiprocessing
import sqlite3

import pytest

from soc_agent.evaluation import EvaluationStore, migrate_evaluations
from soc_agent.experience import ExperienceStore, migrate_experiences
from soc_agent.feedback import FeedbackStore, Verdict, migrate_feedback
from soc_agent.improvement_dataset import (
    ImprovementDatasetBuilder,
    ImprovementDatasetStore,
    migrate_datasets,
    schema,
)
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import (
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from tests.integration.experience.test_storage import table_snapshot

from .conftest import build, submit


def reopen(path):
    return ImprovementDatasetStore(
        FeedbackStore(EvaluationStore(ExperienceStore(SQLiteGovernanceStore(path))))
    )


def process_build(path, identity, barrier, queue):
    store = reopen(path)
    barrier.wait(timeout=20)
    value = ImprovementDatasetBuilder(store).build((identity,))
    queue.put(value.model_dump_json())


def test_process_race_restart(dataset_case):
    c = dataset_case
    submit(c)
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=process_build,
            args=(c.store.database.path, c.evaluation.evaluation_id, barrier, queue),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    try:
        results = [queue.get(timeout=45) for _ in processes]
    finally:
        for process in processes:
            process.join(timeout=20)
            if process.is_alive():
                process.terminate()
                process.join()
    assert all(p.exitcode == 0 for p in processes)
    assert results[0] == results[1]
    store = reopen(c.store.database.path)
    (dataset,) = store.list_datasets()
    assert dataset.model_dump_json() == results[0]
    assert ImprovementDatasetBuilder(store).build((c.evaluation.evaluation_id,)) == dataset
    assert store.export_json(dataset.dataset_id) == c.datasets.export_json(dataset.dataset_id)


def test_canonical_identity_and_counts(dataset_case):
    c = dataset_case
    from soc_agent.feedback import DiagnosticLabel

    submit(c, Verdict.INCORRECT, (DiagnosticLabel.FALSE_NEGATIVE,))
    value = build(c)
    assert c.builder.build([c.evaluation.evaluation_id] * 3) == value
    changed_time = value.model_copy(update={"created_at": value.created_at.replace(year=2000)})
    assert changed_time.manifest_digest == value.manifest_digest
    assert c.datasets.statistics(value.dataset_id).model_dump() == {
        "sample_count": 1,
        "correct_count": 0,
        "incorrect_count": 1,
        "false_positive_count": 0,
        "false_negative_count": 1,
        "exclusion_count": 0,
        "disagreement_count": 0,
    }
    submit(c, Verdict.CORRECT, subject="bob")
    other = build(c)
    counts = c.datasets.statistics(other.dataset_id)
    assert counts.sample_count == 0 and counts.exclusion_count == counts.disagreement_count == 1


@pytest.mark.parametrize(
    "table,column",
    [
        ("improvement_samples", "digest"),
        ("improvement_datasets", "digest"),
        ("dataset_sample_membership", "position"),
    ],
)
def test_snapshot_tampering_fails_closed(dataset_case, table, column):
    c = dataset_case
    submit(c)
    value = build(c)
    with c.store.database.transaction() as connection:
        connection.execute(
            f"UPDATE {table} SET {column}=?", (9 if column == "position" else "0" * 64,)
        )
    with pytest.raises(StoredDataError):
        c.datasets.get_dataset(value.dataset_id)
    with pytest.raises(StoredDataError):
        build(c)


@pytest.mark.parametrize(
    "column,value",
    [
        ("incident_id", "00000000-0000-0000-0000-000000000000"),
        ("experience_id", "0" * 64),
        ("evaluation_id", "0" * 64),
    ],
)
def test_foreign_feedback_binding_fails_closed(dataset_case, column, value):
    c = dataset_case
    feedback = submit(c)
    # Use a raw connection only to simulate corruption that bypasses FK enforcement.
    with sqlite3.connect(c.store.database.path) as connection:
        connection.execute(f"UPDATE analyst_feedback SET {column}=?", (value,))
    if column == "evaluation_id":
        # A pinned dataset reference must never silently accept the relocated feedback.
        from soc_agent.improvement_dataset.models import ArtifactReference, SourceSnapshot
        from soc_agent.improvement_dataset.selection import load_sources
        from soc_agent.review.identity import content_digest

        pinned = SourceSnapshot(
            incident_id=c.incident_id,
            experience=ArtifactReference(
                identity=c.experience.experience_id, digest=content_digest(c.experience)
            ),
            evaluation=ArtifactReference(
                identity=c.evaluation.evaluation_id, digest=content_digest(c.evaluation)
            ),
            feedback=(
                ArtifactReference(identity=feedback.feedback_id, digest=content_digest(feedback)),
            ),
        )
        with c.store.database.transaction(write=False) as connection:
            with pytest.raises(StoredDataError):
                load_sources(
                    connection, c.feedback_store, c.evaluation.evaluation_id, pinned=pinned
                )
    else:
        with pytest.raises(StoredDataError):
            build(c)


def test_migration_preservation_rollback_future(feedback_case, monkeypatch):
    c = feedback_case
    submit(c)
    before = table_snapshot(c.store.database)
    assert all(
        before[name]
        for name in (
            "experiences",
            "evaluations",
            "analyst_feedback",
            "human_confirmations",
            "incidents",
        )
    )
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_datasets(c.store.database)
    assert table_snapshot(c.store.database) == before
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
    migrate_datasets(c.store.database)
    migrate_datasets(c.store.database)
    after = table_snapshot(c.store.database)
    assert {name: after[name] for name in before} == before
    assert reopen(c.store.database.path).list_datasets() == ()
    with sqlite3.connect(c.store.database.path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        reopen(c.store.database.path)


def test_fresh_chain(tmp_path):
    from soc_agent.execution.durable.schema import migrate
    from soc_agent.investigation.runtime.persistence import migrate_checkpoints
    from soc_agent.review.persistence.confirmations import migrate_confirmations

    governance = SQLiteGovernanceStore.create(tmp_path / "fresh.sqlite")
    with pytest.raises(UnsupportedSchemaError):
        migrate_datasets(governance.database)
    for migration in (
        migrate,
        migrate_confirmations,
        migrate_checkpoints,
        migrate_experiences,
        migrate_evaluations,
        migrate_feedback,
        migrate_datasets,
    ):
        migration(governance.database)
    store = reopen(governance.database.path)
    dataset = ImprovementDatasetBuilder(store).build(())
    assert dataset.manifest.sample_count == 0
    assert store.list_samples(dataset.dataset_id) == ()


def test_rechecks_manifest_beyond_outer_checksum(dataset_case):
    from soc_agent.review.identity import content_digest
    from soc_agent.review.persistence import ledger

    c = dataset_case
    submit(c)
    value = build(c)
    forged = value.model_copy(
        update={"manifest": value.manifest.model_copy(update={"sample_count": 2})}
    )
    with c.store.database.transaction() as connection:
        connection.execute(
            "UPDATE improvement_datasets SET payload=?,digest=?",
            (ledger.serialize(forged), content_digest(forged)),
        )
    with pytest.raises(StoredDataError):
        c.datasets.export_json(value.dataset_id)
