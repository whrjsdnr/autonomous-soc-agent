import multiprocessing

import pytest

from soc_agent.improvement_candidates.models import CoverageProposal
from soc_agent.offline_comparison import (
    CoverageConfiguration,
    OfflineEvaluationRunner,
    migrate_frozen_baselines,
    schema,
)
from soc_agent.offline_comparison.models import VerdictState
from soc_agent.offline_evaluation import HardInvariant
from soc_agent.offline_evaluation.models import MetricName
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import (
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from soc_agent.tools.enums import ToolPermission
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.offline_comparison.test_storage import reopen

OFFLINE = {
    "offline_candidate_variants",
    "offline_evaluation_results",
    "offline_comparisons",
    "frozen_offline_baselines",
}


def test_measured_vertical_slice_provenance_restart_and_authority(coverage_case, monkeypatch):
    from soc_agent.assessment import prompts as assessment_prompts
    from soc_agent.planning import prompts as planning_prompts
    from soc_agent.policy import PolicyEngine

    c = coverage_case
    before = table_snapshot(c.store.database)
    state = c.store.load(c.incident_id)
    prompts = assessment_prompts.SYSTEM_PROMPT, planning_prompts.SYSTEM_PROMPT
    cases = [c, *c.children]
    calls = [{name: mock.call_count for name, mock in case.mocks.items()} for case in cases]

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline coverage invoked production authority")

    for case in cases:
        for obj, attr in (
            (case.runtime, "advance"),
            (case.executor, "execute"),
            (case.feedback, "submit"),
            (case.evaluator, "evaluate"),
            (case.llm, "generate_structured"),
            (case.planner_llm, "generate_structured"),
        ):
            monkeypatch.setattr(obj, attr, forbidden)
    monkeypatch.setattr(PolicyEngine, "evaluate", forbidden)
    result = c.runner.evaluate(
        c.plan.plan_id,
        baseline_id=c.baseline.baseline_id,
        expected_baseline_digest=content_digest(c.baseline.content),
    )
    assert result.variant.content.configuration.covered_permissions == (
        ToolPermission.NETWORK_READ,
        ToolPermission.SYSTEM_READ,
    )
    b, candidate = result.baseline_result.content, result.candidate_result.content
    assert (
        b.cases == candidate.cases
        and b.execution_status == candidate.execution_status == "EXECUTED"
    )
    assert b.binding.frozen_baseline.identity == c.baseline.baseline_id
    assert b.binding.source.dataset.manifest_digest == c.dataset.manifest_digest
    assert len(b.cases) >= 2
    feedback_refs = {(f.feedback_id, content_digest(f)) for f in c.holdout_feedback}
    for case in b.cases:
        assert case.content.coverage.required_permissions == (ToolPermission.NETWORK_READ,)
        assert {
            (r.identity, r.digest) for r in case.content.coverage.feedback_refs
        } <= feedback_refs
        assert case.content.facts.sources.incident_id != c.incident_id
    metric = next(
        m for m in result.comparison.content.metrics if m.metric == MetricName.MISSED_PATHS
    )
    assert metric.baseline.value == len(b.cases) and metric.candidate.value == 0
    assert metric.delta == -len(b.cases) and metric.outcome == "IMPROVED"
    assert (
        next(
            s
            for s in result.comparison.content.safety
            if s.invariant == HardInvariant.NO_POLICY_BYPASS
        ).candidate
        == VerdictState.UNKNOWN
    )
    assert c.runner.evaluate(c.plan.plan_id, baseline_id=c.baseline.baseline_id) == result
    store = reopen(c.store.database.path)
    assert store.get_baseline(c.baseline.baseline_id) == c.baseline
    assert store.get_variant(result.variant.variant_id) == result.variant
    assert store.get_evaluation_result(result.baseline_result.result_id) == result.baseline_result
    assert store.get_comparison(result.comparison.comparison_id) == result.comparison
    after = table_snapshot(c.store.database)
    assert all(after[name] == rows for name, rows in before.items() if name not in OFFLINE)
    assert c.store.load(c.incident_id) == state
    assert prompts == (assessment_prompts.SYSTEM_PROMPT, planning_prompts.SYSTEM_PROMPT)
    assert calls == [{name: mock.call_count for name, mock in case.mocks.items()} for case in cases]
    # Generation remains REVIEW-only, even after explicit declaration.
    assert all(
        not isinstance(v.content.proposal, CoverageProposal)
        for v in c.improvement.propose(c.dataset.dataset_id).candidates
    )


def test_explicit_capture_no_auto_selection_digest_and_baseline_snapshot(coverage_case):
    c = coverage_case
    no_baseline = c.runner.evaluate(c.plan.plan_id)
    assert no_baseline.variant.content.configuration is None
    assert "BASELINE_UNAVAILABLE" in no_baseline.baseline_result.content.blockers
    with pytest.raises(ValueError):
        c.comparison_store.capture_baseline(
            target_reference="unprovable.production.prompt", configuration=CoverageConfiguration()
        )
    with pytest.raises(StoredDataError):
        c.runner.evaluate(
            c.plan.plan_id, baseline_id=c.baseline.baseline_id, expected_baseline_digest="0" * 64
        )
    with pytest.raises(StoredDataError):
        c.runner.evaluate(c.plan.plan_id, baseline_id="0" * 64)
    old = c.runner.evaluate(c.plan.plan_id, baseline_id=c.baseline.baseline_id)
    assert (
        c.comparison_store.capture_baseline(
            target_reference=c.baseline.content.target_reference,
            configuration=c.baseline.content.configuration,
        )
        == c.baseline
    )
    other = c.comparison_store.capture_baseline(
        target_reference=c.baseline.content.target_reference,
        configuration=CoverageConfiguration(covered_permissions=(ToolPermission.NETWORK_READ,)),
    )
    new = c.runner.evaluate(c.plan.plan_id, baseline_id=other.baseline_id)
    assert new.comparison.comparison_id != old.comparison.comparison_id
    assert (
        next(
            m for m in new.comparison.content.metrics if m.metric == MetricName.MISSED_PATHS
        ).outcome
        == "UNCHANGED"
    )
    assert c.comparison_store.get_comparison(old.comparison.comparison_id) == old.comparison


def execution_process(path, plan_id, baseline_id, barrier, queue):
    runner = OfflineEvaluationRunner(reopen(path))
    barrier.wait(timeout=20)
    queue.put(runner.evaluate(plan_id, baseline_id=baseline_id).model_dump_json())


def test_measured_process_race(coverage_case):
    c = coverage_case
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=execution_process,
            args=(c.store.database.path, c.plan.plan_id, c.baseline.baseline_id, barrier, queue),
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
    assert all(process.exitcode == 0 for process in processes)
    assert results[0] == results[1]
    assert len(reopen(c.store.database.path).list_results(c.candidate.candidate_id)) == 2


def test_new_proposal_snapshot_and_missing_baseline_fail_closed(coverage_case):
    c = coverage_case
    old = c.runner.evaluate(c.plan.plan_id, baseline_id=c.baseline.baseline_id)
    candidate = c.candidates.declare_coverage_proposal(
        c.review.candidate_id, required_permission=ToolPermission.FILE_READ
    )
    assert candidate.candidate_id != c.candidate.candidate_id
    assert c.comparison_store.list_results(candidate.candidate_id) == ()
    plan = c.offline_planner.plan(candidate.candidate_id).test_plan
    new = c.runner.evaluate(plan.plan_id, baseline_id=c.baseline.baseline_id)
    assert new.candidate_result.result_id != old.candidate_result.result_id
    assert c.comparison_store.get_comparison(old.comparison.comparison_id) == old.comparison
    with c.store.database.transaction() as connection:
        connection.execute(
            "DELETE FROM frozen_offline_baselines WHERE baseline_id=?", (c.baseline.baseline_id,)
        )
    with pytest.raises(StoredDataError):
        c.comparison_store.get_comparison(old.comparison.comparison_id)


def test_baseline_migration_preservation_rollback_and_future(planning_case, monkeypatch):
    import sqlite3

    from tests.integration.offline_comparison.test_storage import setup

    c = setup(planning_case)
    c.runner.evaluate(c.plan.plan_id)
    before = table_snapshot(c.store.database)
    with monkeypatch.context() as patch:
        patch.setattr(schema, "BASELINE_STATEMENTS", schema.BASELINE_STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_frozen_baselines(c.store.database)
    assert table_snapshot(c.store.database) == before
    migrate_frozen_baselines(c.store.database)
    migrate_frozen_baselines(c.store.database)
    after = table_snapshot(c.store.database)
    assert all(after[name] == rows for name, rows in before.items())
    assert (
        c.runner.evaluate(c.plan.plan_id).baseline_result.content.execution_status == "NOT_EXECUTED"
    )
    with sqlite3.connect(c.store.database.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 12
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        reopen(c.store.database.path)


def test_declared_parent_and_human_ground_truth_tampering_rejected(coverage_case):
    from soc_agent.feedback.models import CoverageExpectation
    from soc_agent.review.persistence import ledger

    c = coverage_case
    result = c.runner.evaluate(c.plan.plan_id, baseline_id=c.baseline.baseline_id)
    proposal = c.candidate.content.proposal.model_copy(
        update={
            "review_candidate": c.candidate.content.proposal.review_candidate.model_copy(
                update={"digest": "0" * 64}
            )
        }
    )
    content = c.candidate.content.model_copy(update={"proposal": proposal})
    identity = content_digest(content)
    forged = c.candidate.model_copy(
        update={"candidate_id": identity, "candidate_version": identity, "content": content}
    )
    with c.store.database.transaction() as connection:
        connection.execute(
            "INSERT INTO improvement_candidates VALUES (?,?,?,?,?,?)",
            (
                identity,
                c.dataset.dataset_id,
                content.failure_pattern_refs[0].identity,
                content.candidate_type.value,
                ledger.serialize(forged),
                content_digest(forged),
            ),
        )
    with pytest.raises(StoredDataError):
        c.candidates.get_candidate(identity)
    feedback = c.holdout_feedback[0]
    request = feedback.request.model_copy(
        update={
            "coverage_expectation": CoverageExpectation(
                required_permissions=(ToolPermission.FILE_READ,)
            )
        }
    )
    altered = feedback.model_copy(update={"request": request})
    with c.store.database.transaction() as connection:
        connection.execute(
            "UPDATE analyst_feedback SET payload=?,digest=? WHERE feedback_id=?",
            (ledger.serialize(altered), content_digest(altered), feedback.feedback_id),
        )
    with pytest.raises(StoredDataError):
        c.comparison_store.get_comparison(result.comparison.comparison_id)
