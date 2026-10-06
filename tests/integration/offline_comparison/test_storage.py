import multiprocessing
import sqlite3

import pytest

from soc_agent.offline_comparison import (
    OfflineComparisonStore,
    OfflineEvaluationRunner,
    migrate_offline_comparison,
    schema,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import (
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.offline_evaluation.test_storage import reopen as planning_store

TABLES = {"offline_candidate_variants", "offline_evaluation_results", "offline_comparisons"}


def setup(c):
    c.plan = c.offline_planner.plan(c.candidate.candidate_id).test_plan
    migrate_offline_comparison(c.store.database)
    c.comparison_store = OfflineComparisonStore(c.offline)
    c.runner = OfflineEvaluationRunner(c.comparison_store)
    return c


def reopen(path):
    return OfflineComparisonStore(planning_store(path))


def test_durable_idempotent_query_restart_and_no_production_mutation(planning_case, monkeypatch):
    c = setup(planning_case)
    before = table_snapshot(c.store.database)
    state = c.store.load(c.incident_id)
    calls = {name: m.call_count for name, m in c.mocks.items()}

    def forbidden(*args, **kwargs):
        raise AssertionError("Production operation invoked")

    for obj, name in (
        (c.runtime, "advance"),
        (c.executor, "execute"),
        (c.feedback, "submit"),
        (c.evaluator, "evaluate"),
        (c.llm, "generate_structured"),
    ):
        monkeypatch.setattr(obj, name, forbidden)
    result = c.runner.evaluate(c.plan.plan_id)
    assert c.runner.evaluate(c.plan.plan_id) == result
    other = reopen(c.store.database.path)
    assert other.get_variant(result.variant.variant_id) == result.variant
    assert other.get_evaluation_result(result.baseline_result.result_id) == result.baseline_result
    assert other.get_comparison(result.comparison.comparison_id) == result.comparison
    assert len(other.list_variants(c.candidate.candidate_id)) == 1
    assert len(other.list_results(c.candidate.candidate_id)) == 2
    assert len(other.list_comparisons(c.candidate.candidate_id)) == 1
    assert c.store.load(c.incident_id) == state
    assert calls == {name: m.call_count for name, m in c.mocks.items()}
    after = table_snapshot(c.store.database)
    assert all(after[name] == rows for name, rows in before.items() if name not in TABLES)
    with pytest.raises(StoredDataError):
        c.runner.evaluate(c.plan.plan_id, expected_plan_digest="0" * 64)


def process_run(path, plan_id, barrier, queue):
    runner = OfflineEvaluationRunner(reopen(path))
    barrier.wait(timeout=20)
    queue.put(runner.evaluate(plan_id).model_dump_json())


def test_independent_process_race(planning_case):
    c = setup(planning_case)
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=process_run, args=(c.store.database.path, c.plan.plan_id, barrier, queue)
        )
        for _ in range(2)
    ]
    for p in processes:
        p.start()
    try:
        results = [queue.get(timeout=60) for _ in processes]
    finally:
        for p in processes:
            p.join(timeout=20)
            if p.is_alive():
                p.terminate()
                p.join()
    assert all(p.exitcode == 0 for p in processes)
    assert results[0] == results[1]
    assert len(reopen(c.store.database.path).list_results(c.candidate.candidate_id)) == 2


@pytest.mark.parametrize("table", sorted(TABLES))
def test_checksum_correct_tampering_rejected(planning_case, table):
    c = setup(planning_case)
    result = c.runner.evaluate(c.plan.plan_id)
    value = {
        "offline_candidate_variants": result.variant,
        "offline_evaluation_results": result.baseline_result,
        "offline_comparisons": result.comparison,
    }[table]
    binding = value.content.binding.model_copy(
        update={"split": value.content.binding.split.model_copy(update={"digest": "0" * 64})}
    )
    content = value.content.model_copy(update={"binding": binding})
    key = {
        "offline_candidate_variants": "variant_id",
        "offline_evaluation_results": "result_id",
        "offline_comparisons": "comparison_id",
    }[table]
    updates = {"content": content, key: content_digest(content)}
    if table == "offline_candidate_variants":
        updates["variant_version"] = content_digest(content)
    forged = value.model_copy(update=updates)
    with c.store.database.transaction() as connection:
        connection.execute(
            f"INSERT INTO {table} VALUES (?,?,?,?,?)",
            (
                content_digest(content),
                c.plan.plan_id,
                c.candidate.candidate_id,
                ledger.serialize(forged),
                content_digest(forged),
            ),
        )
    query = {
        "offline_candidate_variants": c.comparison_store.get_variant,
        "offline_evaluation_results": c.comparison_store.get_evaluation_result,
        "offline_comparisons": c.comparison_store.get_comparison,
    }[table]
    with pytest.raises(StoredDataError):
        query(content_digest(content))


def test_source_corruption_fails_before_artifact_insert(planning_case):
    c = setup(planning_case)
    with c.store.database.transaction() as connection:
        connection.execute("UPDATE analyst_feedback SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        c.runner.evaluate(c.plan.plan_id)
    assert all(table_snapshot(c.store.database)[table] == () for table in TABLES)


def test_migration_preserves_records_rollback_and_future_schema(planning_case, monkeypatch):
    c = planning_case
    c.offline_planner.plan(c.candidate.candidate_id)
    before = table_snapshot(c.store.database)
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_offline_comparison(c.store.database)
    assert table_snapshot(c.store.database) == before
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
    migrate_offline_comparison(c.store.database)
    migrate_offline_comparison(c.store.database)
    after = table_snapshot(c.store.database)
    assert all(after[name] == rows for name, rows in before.items())
    with sqlite3.connect(c.store.database.path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        reopen(c.store.database.path)


def test_missing_offline_parent_and_new_plan_snapshot(planning_case):
    from soc_agent.offline_evaluation import OfflineEvaluationPlanner, SplitConfig

    c = setup(planning_case)
    old = c.runner.evaluate(c.plan.plan_id)
    new_plan = (
        OfflineEvaluationPlanner(c.offline, split_config=SplitConfig(bucket_count=7))
        .plan(c.candidate.candidate_id)
        .test_plan
    )
    new = c.runner.evaluate(new_plan.plan_id)
    assert new.baseline_result.result_id != old.baseline_result.result_id
    assert c.comparison_store.get_comparison(old.comparison.comparison_id) == old.comparison
    with c.store.database.transaction() as connection:
        connection.execute(
            "DELETE FROM offline_candidate_variants WHERE id=?", (old.variant.variant_id,)
        )
    with pytest.raises(StoredDataError):
        c.comparison_store.get_evaluation_result(old.candidate_result.result_id)
    with pytest.raises(StoredDataError):
        c.comparison_store.get_comparison(old.comparison.comparison_id)


def test_fresh_database_chain(tmp_path):
    from soc_agent.evaluation import migrate_evaluations
    from soc_agent.execution.durable.schema import migrate
    from soc_agent.experience import migrate_experiences
    from soc_agent.feedback import migrate_feedback
    from soc_agent.improvement_candidates import migrate_candidates
    from soc_agent.improvement_dataset import migrate_datasets
    from soc_agent.investigation.runtime.persistence import migrate_checkpoints
    from soc_agent.offline_evaluation import migrate_offline_evaluation
    from soc_agent.review.persistence import SQLiteGovernanceStore
    from soc_agent.review.persistence.confirmations import migrate_confirmations

    governance = SQLiteGovernanceStore.create(tmp_path / "fresh.sqlite")
    with pytest.raises(UnsupportedSchemaError):
        migrate_offline_comparison(governance.database)
    for migration in (
        migrate,
        migrate_confirmations,
        migrate_checkpoints,
        migrate_experiences,
        migrate_evaluations,
        migrate_feedback,
        migrate_datasets,
        migrate_candidates,
        migrate_offline_evaluation,
        migrate_offline_comparison,
    ):
        migration(governance.database)
    store = reopen(governance.database.path)
    with pytest.raises(StoredDataError):
        OfflineEvaluationRunner(store).evaluate("0" * 64)
    assert all(table_snapshot(store.database)[table] == () for table in TABLES)


def test_new_dataset_candidate_does_not_rebind_old_results(planning_case):
    from soc_agent.feedback import DiagnosticLabel, Verdict
    from tests.integration.improvement_dataset.conftest import submit

    c = setup(planning_case)
    old = c.runner.evaluate(c.plan.plan_id)
    submit(c, Verdict.INCORRECT, (DiagnosticLabel.UNNECESSARY_INVESTIGATION,), subject="bob")
    dataset = c.builder.build(s.sources.evaluation.identity for s in c.dataset.manifest.selection)
    proposals = c.improvement.propose(dataset.dataset_id)
    candidate = next(
        v
        for v in proposals.candidates
        if v.content.candidate_type == c.candidate.content.candidate_type
    )
    assert c.comparison_store.list_results(candidate.candidate_id) == ()
    plan = c.offline_planner.plan(candidate.candidate_id).test_plan
    new = c.runner.evaluate(plan.plan_id)
    assert new.baseline_result.content.binding.source.dataset.dataset_id == dataset.dataset_id
    assert new.baseline_result.result_id != old.baseline_result.result_id
    assert c.runner.evaluate(c.plan.plan_id) == old
