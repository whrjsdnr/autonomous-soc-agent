"""Trusted feedback -> rebuilt snapshot -> measured comparison -> human review only."""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.feedback.conftest import issue as feedback_issue
from tests.integration.improvement_review.test_review import issue, submission
from tests.integration.offline_comparison.test_storage import reopen

from soc_agent.feedback import CoverageExpectation, InvestigationPathAdjudication
from soc_agent.improvement_candidates import CandidateType
from soc_agent.improvement_promotion import PromotionEligibilityService, PromotionReason
from soc_agent.improvement_review import ImprovementReviewStore, ReviewDecision
from soc_agent.offline_comparison import CoverageConfiguration
from soc_agent.offline_comparison.models import CONTRACT_EVALUATOR_VERSION, ValueState, VerdictState
from soc_agent.offline_evaluation import OfflineEvaluationPlanner, SplitConfig
from soc_agent.offline_evaluation.models import MetricName
from soc_agent.offline_evaluation.split import partition
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.state.evidence import utc_now
from soc_agent.tools.enums import ToolPermission as P


def supply_human_facts(source, completeness, unnecessary):
    receipts = []
    for child, previous in zip(source.children, source.holdout_feedback, strict=True):
        request = previous.request.model_copy(
            update={
                "submission_id": uuid4(),
                "coverage_expectation": CoverageExpectation(
                    required_permissions=(P.NETWORK_READ,),
                    path_adjudication=InvestigationPathAdjudication(
                        unnecessary_permissions=unnecessary, review_completeness=completeness
                    ),
                ),
            }
        )
        child.boundary.now = utc_now()
        receipts.append(child.feedback.submit(request, credential=feedback_issue(child, request)))
    return receipts


def rebuild_and_plan(source, required):
    dataset = source.builder.build(
        tuple(s.sources.evaluation.identity for s in source.dataset.manifest.selection)
    )
    generated = source.improvement.propose(dataset.dataset_id)
    review = next(
        c
        for c in generated.candidates
        if c.content.candidate_type == CandidateType.INVESTIGATION_STRATEGY
    )
    candidate = source.candidates.declare_coverage_proposal(
        review.candidate_id, required_permission=required
    )
    with source.store.database.transaction(write=False) as connection:
        binding, facts = source.candidates._context(connection, dataset.dataset_id)
    config = next(
        SplitConfig(bucket_count=n, holdout_buckets=n - 1)
        for n in range(2, 32)
        if len(
            partition(
                binding,
                facts,
                candidate.content.supporting_sample_refs,
                SplitConfig(bucket_count=n, holdout_buckets=n - 1),
            ).content.holdout
        )
        >= 2
    )
    return dataset, OfflineEvaluationPlanner(source.offline, split_config=config).plan(
        candidate.candidate_id
    ).test_plan


def evaluate(source, plan, paths):
    baseline = source.comparison_store.capture_baseline(
        target_reference="soc_agent.planning.models.PlannerInput",
        configuration=CoverageConfiguration(covered_permissions=paths),
    )
    return source.runner.evaluate(
        plan.plan_id, baseline_id=baseline.baseline_id, evaluator_version=CONTRACT_EVALUATOR_VERSION
    )


@pytest.mark.parametrize("regression", [False, True])
def test_trusted_adjudication_snapshot_measured_review_and_eligibility(
    review_case, monkeypatch, regression
):
    c, source = review_case, review_case.source
    before = table_snapshot(c.store.database)

    def forbidden(*args, **kwargs):
        raise AssertionError("Adjudication reached production capability")

    for obj, attribute in (
        (source.runtime, "advance"),
        (source.executor, "execute"),
        (source.llm, "generate_structured"),
    ):
        monkeypatch.setattr(obj, attribute, forbidden)
    old_record_value = submission(c, ReviewDecision.DEFER)
    c.boundary.now = utc_now()
    old_record = c.service.submit(old_record_value, credential=issue(c, old_record_value))
    # PARTIAL is real trusted feedback, but it cannot remove the required-acceptance blocker.
    partial = supply_human_facts(source, "PARTIAL", (P.SYSTEM_READ,) if regression else ())
    partial_dataset, partial_plan = rebuild_and_plan(
        source, P.SYSTEM_READ if regression else P.NETWORK_READ
    )
    partial_artifacts = evaluate(source, partial_plan, (P.NETWORK_READ,))
    partial_request = c.store.create_request(partial_artifacts.comparison.comparison_id)
    partial_eligibility = PromotionEligibilityService(c.store).assess(
        partial_request.review_request_id
    )
    assert partial_eligibility.status == "NON_PROMOTABLE"
    assert PromotionReason.ACCEPTANCE_NOT_PASS in partial_eligibility.reasons
    assert any(
        m.candidate.state == ValueState.NOT_MEASURABLE
        for m in partial_artifacts.comparison.content.metrics
        if m.metric == MetricName.UNNECESSARY_PATHS
    )
    receipts = supply_human_facts(source, "COMPLETE", (P.SYSTEM_READ,) if regression else ())
    dataset, plan = rebuild_and_plan(source, P.SYSTEM_READ if regression else P.NETWORK_READ)
    assert dataset.dataset_id != partial_dataset.dataset_id != source.dataset.dataset_id
    assert source.datasets.get_dataset(source.dataset.dataset_id) == source.dataset
    assert source.datasets.get_dataset(partial_dataset.dataset_id) == partial_dataset
    artifacts = evaluate(source, plan, (P.NETWORK_READ,) if regression else (P.SYSTEM_READ,))
    assert artifacts.baseline_result.content.cases == artifacts.candidate_result.content.cases
    specification = source.offline.get_specification(plan.content.specification.identity)
    assert (
        tuple(case.content.facts.sample for case in artifacts.candidate_result.content.cases)
        == specification.content.partition.content.holdout
    )
    pinned = {
        a.feedback.identity
        for case in artifacts.candidate_result.content.cases
        for a in case.content.coverage.path_adjudications
    }
    assert pinned <= {f.feedback_id for f in receipts + partial}
    assert pinned & {f.feedback_id for f in receipts}
    for case in artifacts.candidate_result.content.cases:
        for adjudicated in case.content.coverage.path_adjudications:
            feedback = next(
                f for f in receipts + partial if f.feedback_id == adjudicated.feedback.identity
            )
            assert adjudicated.feedback.digest == content_digest(feedback)
            assert adjudicated.feedback in case.content.facts.sources.feedback
            assert (
                adjudicated.adjudication == feedback.request.coverage_expectation.path_adjudication
            )
    request = c.store.create_request(artifacts.comparison.comparison_id)
    assert request.content.candidate_safety_counts == (10, 0, 0)
    current = SimpleNamespace(request=request, boundary=c.boundary)
    metric = next(
        m for m in artifacts.comparison.content.metrics if m.metric == MetricName.UNNECESSARY_PATHS
    )
    criterion = next(
        a
        for a in artifacts.comparison.content.acceptance
        if a.metric == MetricName.UNNECESSARY_PATHS
    )
    service = PromotionEligibilityService(c.store)
    assert service.assess(request.review_request_id).status == "NON_PROMOTABLE"
    assert c.store.get_review_record_for_request(request.review_request_id) is None
    assert metric.baseline.value == 0
    if regression:
        assert metric.candidate.value == len(artifacts.candidate_result.content.cases)
        assert criterion.status == VerdictState.FAIL
        value = submission(current, ReviewDecision.APPROVE)
        with pytest.raises(HumanAuthorizationDenied):
            c.service.submit(value, credential=issue(current, value))
        assert (
            PromotionReason.ACCEPTANCE_NOT_PASS in service.assess(request.review_request_id).reasons
        )
    else:
        assert metric.candidate.value == 0 and criterion.status == VerdictState.PASS
        assert all(a.status == VerdictState.PASS for a in artifacts.comparison.content.acceptance)
        assert service.assess(request.review_request_id).reasons == (
            PromotionReason.REVIEW_NOT_APPROVED,
        )
        c.boundary.now = utc_now()
        value = submission(current, ReviewDecision.APPROVE)
        record = c.service.submit(value, credential=issue(current, value))
        assert record.submission.decision == ReviewDecision.APPROVE
        assert service.assess(request.review_request_id).status == "PROMOTABLE"
        # Independent immutable graphs let REJECT/DEFER remain terminal without overwrites.
        for decision, paths in (
            (ReviewDecision.REJECT, (P.FILE_READ,)),
            (ReviewDecision.DEFER, (P.NETWORK_READ,)),
        ):
            other = evaluate(source, plan, paths)
            other_request = c.store.create_request(other.comparison.comparison_id)
            context = SimpleNamespace(request=other_request, boundary=c.boundary)
            c.boundary.now = utc_now()
            value = submission(context, decision)
            c.service.submit(value, credential=issue(context, value))
            assert service.assess(other_request.review_request_id).reasons == (
                PromotionReason.REVIEW_NOT_APPROVED,
            )
        restarted = ImprovementReviewStore(reopen(c.store.database.path))
        assert restarted.get_review_record(record.review_record_id) == record
        assert (
            PromotionEligibilityService(restarted).assess(request.review_request_id).status
            == "PROMOTABLE"
        )
        feedback = receipts[0]
        with c.store.database.transaction() as connection:
            row = connection.execute(
                "SELECT digest FROM analyst_feedback WHERE feedback_id=?", (feedback.feedback_id,)
            ).fetchone()
            connection.execute(
                "UPDATE analyst_feedback SET digest=? WHERE feedback_id=?",
                ("0" * 64, feedback.feedback_id),
            )
        try:
            with pytest.raises(StoredDataError):
                service.assess(request.review_request_id)
        finally:
            with c.store.database.transaction() as connection:
                connection.execute(
                    "UPDATE analyst_feedback SET digest=? WHERE feedback_id=?",
                    (row["digest"], feedback.feedback_id),
                )
    assert c.store.get_review_request(c.request.review_request_id) == c.request
    assert c.store.get_review_record(old_record.review_record_id) == old_record
    after = table_snapshot(c.store.database)
    for table in before:
        if table not in {
            "analyst_feedback",
            "feedback_audit",
            "human_confirmations",
            "improvement_samples",
            "improvement_datasets",
            "dataset_sample_membership",
            "improvement_dataset_statistics",
            "failure_patterns",
            "improvement_candidates",
            "offline_evaluation_specifications",
            "candidate_test_plans",
            "offline_candidate_variants",
            "frozen_offline_baselines",
            "offline_evaluation_results",
            "offline_comparisons",
            "improvement_review_requests",
            "improvement_review_records",
        }:
            assert before[table] == after[table], table
    assert not any(
        "promotion" in table or "active_pointer" in table or "rollback" in table for table in after
    )
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 13
