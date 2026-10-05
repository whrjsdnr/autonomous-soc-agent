import multiprocessing
import sqlite3

import pytest

from soc_agent.feedback import DiagnosticLabel, Verdict
from soc_agent.offline_evaluation import (
    OfflineEvaluationPlanner,
    OfflineEvaluationStore,
    SplitConfig,
    migrate_offline_evaluation,
    schema,
)
from soc_agent.offline_evaluation.models import PlanningBlocker
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import (
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.improvement_candidates.test_candidates import reopen as candidate_store
from tests.integration.improvement_dataset.conftest import submit

TABLES = {"offline_evaluation_specifications", "candidate_test_plans"}


def reopen(path):
    return OfflineEvaluationStore(candidate_store(path))


def test_durable_plan_query_idempotency_and_normal_blockers(planning_case):
    c = planning_case
    result = c.offline_planner.plan(
        c.candidate.candidate_id,
        expected_candidate_digest=content_digest(c.candidate.content),
        expected_manifest_digest=c.dataset.manifest_digest,
    )
    s, p = result.specification, result.test_plan
    assert c.offline.get_specification(s.specification_id) == s
    assert c.offline.get_test_plan(p.plan_id) == p
    assert c.offline.list_specifications(c.candidate.candidate_id) == (s,)
    assert c.offline.list_test_plans(c.candidate.candidate_id) == (p,)
    assert c.offline_planner.plan(c.candidate.candidate_id) == result
    assert PlanningBlocker.NO_HOLDOUT in s.content.blockers
    assert s.content.baseline.baseline_reference == "UNKNOWN"
    assert s.content.binding.supporting_pattern_refs == c.candidate.content.failure_pattern_refs
    assert s.content.binding.supporting_sample_refs == c.candidate.content.supporting_sample_refs
    other = OfflineEvaluationPlanner(c.offline, split_config=SplitConfig(bucket_count=7)).plan(
        c.candidate.candidate_id,
    )
    assert other.specification.specification_id != s.specification_id
    assert len(c.offline.list_test_plans(c.candidate.candidate_id)) == 2
    assert tuple(
        plan.plan_id for plan in c.offline.list_test_plans(c.candidate.candidate_id)
    ) == tuple(
        sorted(
            (p.plan_id, other.test_plan.plan_id),
        )
    )
    for method in (c.offline.get_test_plan, c.offline.get_specification):
        with pytest.raises(StoredDataError):
            method("0" * 64)
    for guard in ("expected_candidate_digest", "expected_manifest_digest"):
        with pytest.raises(StoredDataError):
            c.offline_planner.plan(c.candidate.candidate_id, **{guard: "0" * 64})


def process_plan(path, candidate_id, barrier, queue):
    planner = OfflineEvaluationPlanner(reopen(path))
    barrier.wait(timeout=20)
    queue.put(planner.plan(candidate_id).model_dump_json())


def test_independent_process_race_and_restart(planning_case):
    c = planning_case
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=process_plan,
            args=(
                c.store.database.path,
                c.candidate.candidate_id,
                barrier,
                queue,
            ),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    try:
        results = [queue.get(timeout=60) for _ in processes]
    finally:
        for process in processes:
            process.join(timeout=20)
            if process.is_alive():
                process.terminate()
                process.join()
    assert all(p.exitcode == 0 for p in processes)
    assert results[0] == results[1]
    store = reopen(c.store.database.path)
    result = OfflineEvaluationPlanner(store).plan(c.candidate.candidate_id)
    assert result.model_dump_json() == results[0]
    assert len(store.list_specifications(c.candidate.candidate_id)) == 1
    assert len(store.list_test_plans(c.candidate.candidate_id)) == 1


@pytest.mark.parametrize(
    "corruption",
    [
        "candidate_digest",
        "missing_pattern",
        "cross_dataset_pattern",
        "dataset_manifest",
        "sample_membership",
        "evaluation_digest",
        "feedback_digest",
        "forged_candidate_support",
    ],
)
def test_source_graph_corruption_fails_closed(planning_case, corruption):
    c = planning_case
    other_dataset = c.builder.build(()) if corruption == "cross_dataset_pattern" else None
    if corruption == "missing_pattern":
        with sqlite3.connect(c.store.database.path) as connection:
            connection.execute("DELETE FROM failure_patterns")
    else:
        with c.store.database.transaction() as connection:
            if corruption == "candidate_digest":
                connection.execute("UPDATE improvement_candidates SET digest=?", ("0" * 64,))
            elif corruption == "cross_dataset_pattern":
                connection.execute(
                    "UPDATE failure_patterns SET dataset_id=?", (other_dataset.dataset_id,)
                )
            elif corruption == "dataset_manifest":
                connection.execute("UPDATE improvement_datasets SET digest=?", ("0" * 64,))
            elif corruption == "sample_membership":
                connection.execute("DELETE FROM dataset_sample_membership")
            elif corruption == "evaluation_digest":
                connection.execute("UPDATE evaluations SET digest=?", ("0" * 64,))
            elif corruption == "feedback_digest":
                connection.execute("UPDATE analyst_feedback SET digest=?", ("0" * 64,))
            else:
                content = c.candidate.content.model_copy(
                    update={
                        "supporting_sample_refs": c.candidate.content.supporting_sample_refs[:1],
                    }
                )
                identity = content_digest(content)
                forged = c.candidate.model_copy(
                    update={
                        "candidate_id": identity,
                        "candidate_version": identity,
                        "content": content,
                    }
                )
                connection.execute(
                    "UPDATE improvement_candidates SET candidate_id=?,payload=?,digest=? "
                    "WHERE candidate_id=?",
                    (
                        identity,
                        ledger.serialize(forged),
                        content_digest(forged),
                        c.candidate.candidate_id,
                    ),
                )
                c.candidate = forged
    with pytest.raises(StoredDataError):
        c.offline_planner.plan(c.candidate.candidate_id)
    with c.store.database.transaction(write=False) as connection:
        assert (
            connection.execute("SELECT count(*) FROM offline_evaluation_specifications").fetchone()[
                0
            ]
            == 0
        )
        assert connection.execute("SELECT count(*) FROM candidate_test_plans").fetchone()[0] == 0


def test_checksum_correct_specification_and_plan_tampering(planning_case):
    c = planning_case
    result = c.offline_planner.plan(c.candidate.candidate_id)
    spec = result.specification
    content = spec.content.model_copy(
        update={"required_evidence": spec.content.required_evidence[:-1]}
    )
    identity = content_digest(content)
    forged = spec.model_copy(
        update={
            "specification_id": identity,
            "specification_version": identity,
            "content": content,
        }
    )
    with c.store.database.transaction() as connection:
        connection.execute(
            "INSERT INTO offline_evaluation_specifications VALUES (?,?,?,?)",
            (
                identity,
                c.candidate.candidate_id,
                ledger.serialize(forged),
                content_digest(forged),
            ),
        )
    with pytest.raises(StoredDataError):
        c.offline.get_specification(identity)
    plan = result.test_plan
    cases = list(plan.content.ordered_test_cases)
    cases[3], cases[4] = (
        cases[4].model_copy(update={"position": 4}),
        cases[3].model_copy(update={"position": 5}),
    )
    content = plan.content.model_copy(update={"ordered_test_cases": tuple(cases)})
    identity = content_digest(content)
    forged = plan.model_copy(update={"plan_id": identity, "content": content})
    with c.store.database.transaction() as connection:
        connection.execute(
            "INSERT INTO candidate_test_plans VALUES (?,?,?,?,?)",
            (
                identity,
                spec.specification_id,
                c.candidate.candidate_id,
                ledger.serialize(forged),
                content_digest(forged),
            ),
        )
    with pytest.raises(StoredDataError):
        c.offline.get_test_plan(identity)


def test_new_snapshot_requires_explicit_new_candidate_plan(planning_case):
    c = planning_case
    old = c.offline_planner.plan(c.candidate.candidate_id)
    before = table_snapshot(c.store.database)
    # Compatible feedback alters source identity without dropping supervised samples.
    submit(c, Verdict.INCORRECT, (DiagnosticLabel.UNNECESSARY_INVESTIGATION,), subject="bob")
    newer_dataset = c.builder.build(
        s.sources.evaluation.identity for s in c.dataset.manifest.selection
    )
    assert newer_dataset.dataset_id != c.dataset.dataset_id
    newer_proposals = c.improvement.propose(newer_dataset.dataset_id)
    newer_candidate = next(
        candidate
        for candidate in newer_proposals.candidates
        if candidate.content.candidate_type == c.candidate.content.candidate_type
    )
    assert c.offline.list_test_plans(newer_candidate.candidate_id) == ()
    assert c.offline_planner.plan(c.candidate.candidate_id) == old
    newer = c.offline_planner.plan(newer_candidate.candidate_id)
    assert newer.specification.content.binding.dataset.dataset_id == newer_dataset.dataset_id
    assert (
        newer.specification.content.partition.split_id
        != old.specification.content.partition.split_id
    )
    assert newer.specification.specification_id != old.specification.specification_id
    assert c.offline.get_test_plan(old.test_plan.plan_id) == old.test_plan
    after = table_snapshot(c.store.database)
    for table in TABLES:
        assert all(row in after[table] for row in before[table])


def test_no_mutation_execution_variant_or_runtime_authority(planning_case, monkeypatch):
    from soc_agent.assessment import prompts as assessment_prompts
    from soc_agent.planning import prompts as planning_prompts
    from soc_agent.policy import PolicyEngine

    c = planning_case
    before = table_snapshot(c.store.database)
    initial_state = c.store.load(c.incident_id)
    prompt_text = (assessment_prompts.SYSTEM_PROMPT, planning_prompts.SYSTEM_PROMPT)
    calls = {name: mock.call_count for name, mock in c.mocks.items()}

    def forbidden(*args, **kwargs):
        raise AssertionError("Specification planning invoked an authority-bearing operation")

    for obj, attribute in (
        (c.runtime, "advance"),
        (c.executor, "execute"),
        (c.feedback, "submit"),
        (c.evaluator, "evaluate"),
        (c.llm, "generate_structured"),
        (c.improvement, "propose"),
        (PolicyEngine, "evaluate"),
    ):
        monkeypatch.setattr(obj, attribute, forbidden)
    result = c.offline_planner.plan(c.candidate.candidate_id)
    after = table_snapshot(c.store.database)
    assert all(after[name] == rows for name, rows in before.items() if name not in TABLES)
    assert c.store.load(c.incident_id) == initial_state
    assert prompt_text == (assessment_prompts.SYSTEM_PROMPT, planning_prompts.SYSTEM_PROMPT)
    assert calls == {name: mock.call_count for name, mock in c.mocks.items()}
    assert not result.specification.content.variant.generated_by_planner
    assert result.test_plan.content.variant.artifact_reference == "UNKNOWN"


def test_migration_v9_v10_preservation_rollback_future(candidate_case, monkeypatch):
    c = candidate_case
    c.improvement.propose(c.dataset.dataset_id)
    before = table_snapshot(c.store.database)
    assert all(
        before[name]
        for name in (
            "experiences",
            "evaluations",
            "analyst_feedback",
            "improvement_datasets",
            "failure_patterns",
            "improvement_candidates",
            "human_confirmations",
            "incidents",
        )
    )
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 9
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_offline_evaluation(c.store.database)
    assert table_snapshot(c.store.database) == before
    migrate_offline_evaluation(c.store.database)
    migrate_offline_evaluation(c.store.database)
    after = table_snapshot(c.store.database)
    assert {name: after[name] for name in before} == before
    with sqlite3.connect(c.store.database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        reopen(c.store.database.path)


def test_fresh_database_explicit_chain(tmp_path):
    from soc_agent.evaluation import migrate_evaluations
    from soc_agent.execution.durable.schema import migrate
    from soc_agent.experience import migrate_experiences
    from soc_agent.feedback import migrate_feedback
    from soc_agent.improvement_candidates import migrate_candidates
    from soc_agent.improvement_dataset import migrate_datasets
    from soc_agent.investigation.runtime.persistence import migrate_checkpoints
    from soc_agent.review.persistence import SQLiteGovernanceStore
    from soc_agent.review.persistence.confirmations import migrate_confirmations

    governance = SQLiteGovernanceStore.create(tmp_path / "fresh.sqlite")
    with pytest.raises(UnsupportedSchemaError):
        migrate_offline_evaluation(governance.database)
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
    ):
        migration(governance.database)
    store = reopen(governance.database.path)
    with pytest.raises(StoredDataError):
        OfflineEvaluationPlanner(store).plan("0" * 64)
    assert table_snapshot(store.database)["candidate_test_plans"] == ()
