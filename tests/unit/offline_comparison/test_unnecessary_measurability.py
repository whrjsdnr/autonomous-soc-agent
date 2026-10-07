"""Required coverage is not an exhaustive adjudication of unnecessary paths."""

from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.unit.offline_comparison.test_coverage import inputs

from soc_agent.feedback.models import CoverageExpectation, DiagnosticLabel, FeedbackRequest, Verdict
from soc_agent.offline_comparison.coverage_models import CoverageGroundTruth
from soc_agent.offline_comparison.execution import execute_pair
from soc_agent.offline_comparison.models import CONTRACT_EVALUATOR_VERSION, ValueState, VerdictState
from soc_agent.offline_evaluation.models import MetricName
from soc_agent.tools.enums import ToolPermission


def test_overall_unnecessary_label_has_no_path_adjudication_and_legacy_roundtrips():
    request = FeedbackRequest(
        submission_id=UUID(int=1),
        incident_id=UUID(int=2),
        experience_id="1" * 64,
        experience_digest="2" * 64,
        evaluation_id="3" * 64,
        evaluation_digest="4" * 64,
        verdict=Verdict.INCORRECT,
        labels=(DiagnosticLabel.UNNECESSARY_INVESTIGATION,),
    )
    serialized = request.model_dump(mode="json")
    assert request.scope == "overall"
    assert "coverage_expectation" not in serialized
    restored = FeedbackRequest.model_validate(serialized)
    assert restored == request and restored.digest == request.digest
    assert restored.coverage_expectation is None
    expectation = CoverageExpectation(required_permissions=(ToolPermission.NETWORK_READ,))
    assert set(expectation.model_dump()) == {"contract_version", "required_permissions"}
    # No historical field can claim that an unrequired path was adjudicated unnecessary.
    with pytest.raises(ValidationError):
        CoverageExpectation.model_validate(
            {**expectation.model_dump(), "unnecessary_permissions": (ToolPermission.SYSTEM_READ,)}
        )


@pytest.mark.parametrize("has_required_coverage", [True, False])
def test_paired_unnecessary_count_stays_unmeasurable_without_explicit_adjudication(
    has_required_coverage,
):
    source, facts, spec, plan, baseline, truths = inputs()
    if not has_required_coverage:
        truths = {
            key: CoverageGroundTruth(
                status="NOT_MEASURABLE", required_permissions=(), feedback_refs=()
            )
            for key in truths
        }
    artifacts = execute_pair(
        source, spec, plan, facts, baseline, truths, evaluator_version=CONTRACT_EVALUATOR_VERSION
    )
    b, c = artifacts.baseline_result.content, artifacts.candidate_result.content
    assert b.cases == c.cases
    assert b.metric_definitions == c.metric_definitions
    assert tuple(case.content.coverage for case in b.cases) == tuple(
        truths[case.content.facts.sample.identity] for case in c.cases
    )
    if has_required_coverage:
        # SYSTEM_READ is selected but is outside the explicit NETWORK_READ requirement.
        # That observation does not establish an unnecessary investigation.
        assert all(
            ToolPermission.SYSTEM_READ in outcome.trace.selected_permissions
            and ToolPermission.SYSTEM_READ not in outcome.trace.required_permissions
            for outcome in c.per_case_outcomes
        )
    metric = next(
        m for m in artifacts.comparison.content.metrics if m.metric == MetricName.UNNECESSARY_PATHS
    )
    assert metric.baseline.state == metric.candidate.state == ValueState.NOT_MEASURABLE
    assert metric.baseline.value is metric.candidate.value is metric.delta is None
    assert metric.outcome == "NOT_MEASURABLE"
    criterion = next(
        a
        for a in artifacts.comparison.content.acceptance
        if a.metric == MetricName.UNNECESSARY_PATHS
    )
    assert criterion.operator == "NOT_GREATER_THAN_BASELINE"
    assert criterion.status == VerdictState.UNKNOWN
    assert all(
        s.baseline == s.candidate == VerdictState.PASS for s in artifacts.comparison.content.safety
    )
    replay = execute_pair(
        source,
        spec,
        plan,
        tuple(reversed(facts)),
        baseline,
        truths,
        evaluator_version=CONTRACT_EVALUATOR_VERSION,
    )
    # Creation timestamps are metadata; deterministic identities bind logical content.
    assert replay.variant.variant_id == artifacts.variant.variant_id
    assert replay.baseline_result.content == artifacts.baseline_result.content
    assert replay.candidate_result.content == artifacts.candidate_result.content
    assert replay.comparison.comparison_id == artifacts.comparison.comparison_id
