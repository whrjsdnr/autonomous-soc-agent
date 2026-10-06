import hashlib
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.unit.improvement_candidates.test_analysis import fact
from tests.unit.offline_evaluation.test_planning import candidate_for

from soc_agent._json import canonical_json_object
from soc_agent.feedback.models import CoverageExpectation, FeedbackRequest, Verdict
from soc_agent.improvement_candidates.declaration import declare_coverage
from soc_agent.improvement_candidates.models import CandidateType, ImprovementCandidate
from soc_agent.offline_comparison.adapter import measure, safety
from soc_agent.offline_comparison.coverage_models import (
    BaselineContent,
    CoverageConfiguration,
    CoverageGroundTruth,
    CoverageTrace,
    FrozenBaseline,
)
from soc_agent.offline_comparison.evaluation import compare, evaluate_unavailable, reference
from soc_agent.offline_comparison.execution import execute_pair
from soc_agent.offline_comparison.models import (
    CaseOutcome,
    OfflineEvaluationResult,
    ValueState,
    VerdictState,
)
from soc_agent.offline_evaluation import HardInvariant, SplitConfig
from soc_agent.offline_evaluation.models import MetricName
from soc_agent.offline_evaluation.planning import make_test_plan, specify
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.tools.enums import ToolPermission as Permission


def inputs(required=Permission.NETWORK_READ):
    review, support = candidate_for(CandidateType.INVESTIGATION_STRATEGY)
    source = declare_coverage(review, required)
    facts = support + tuple(fact(n, verdict=Verdict.CORRECT) for n in range(3, 24))
    spec = specify(source, facts, SplitConfig(bucket_count=2))
    plan = make_test_plan(spec)
    content = BaselineContent(
        configuration=CoverageConfiguration(covered_permissions=(Permission.SYSTEM_READ,))
    )
    baseline = FrozenBaseline(
        baseline_id=content_digest(content),
        baseline_version=content_digest(content),
        content=content,
    )
    truths = {
        f.sample.identity: CoverageGroundTruth(
            status="MEASURABLE",
            required_permissions=(Permission.NETWORK_READ,),
            feedback_refs=f.sources.feedback,
        )
        for f in facts
        if f.sample in spec.content.partition.content.holdout
    }
    return source, facts, spec, plan, baseline, truths


def test_explicit_contract_exact_transformation_and_paired_measured_replay():
    source, facts, spec, plan, baseline, truths = inputs()
    result = execute_pair(source, spec, plan, facts, baseline, truths)
    assert result.variant.content.construction_status == "CONSTRUCTIBLE"
    assert result.variant.content.structured_offline_change == source.content.proposal
    assert result.variant.content.configuration.covered_permissions == (
        Permission.NETWORK_READ,
        Permission.SYSTEM_READ,
    )
    b, c = result.baseline_result.content, result.candidate_result.content
    assert b.execution_status == c.execution_status == "EXECUTED"
    assert (
        b.cases == c.cases and b.metric_definitions == c.metric_definitions == spec.content.metrics
    )
    assert (
        tuple(case.content.facts.sample for case in b.cases)
        == spec.content.partition.content.holdout
    )
    assert not set(case.content.facts.sources.incident_id for case in b.cases) & set(
        f.sources.incident_id
        for f in facts
        if f.sample in spec.content.partition.content.development
    )
    assert all(
        o.trace.selected_permissions == baseline.content.configuration.covered_permissions
        for o in b.per_case_outcomes
    )
    delta = next(
        m for m in result.comparison.content.metrics if m.metric == MetricName.MISSED_PATHS
    )
    assert delta.baseline.value == len(b.cases)
    assert delta.candidate.value == 0
    assert delta.delta == -len(b.cases) and delta.outcome == "IMPROVED"
    assert all(case.content.facts.verdict == Verdict.CORRECT for case in b.cases)
    assert all(
        i.status == VerdictState.PASS
        for i in c.invariants
        if i.invariant not in (HardInvariant.NO_POLICY_BYPASS, HardInvariant.NO_APPROVAL_BYPASS)
    )
    assert all(
        i.status == VerdictState.UNKNOWN
        for i in c.invariants
        if i.invariant in (HardInvariant.NO_POLICY_BYPASS, HardInvariant.NO_APPROVAL_BYPASS)
    )
    criteria = {a.metric: a.status for a in result.comparison.content.acceptance}
    assert criteria[MetricName.MISSED_PATHS] == VerdictState.PASS
    assert criteria[MetricName.GOVERNANCE_VIOLATIONS] == VerdictState.UNKNOWN
    assert criteria[MetricName.UNAUTHORIZED_WRITES] == VerdictState.PASS
    again = execute_pair(source, spec, plan, tuple(reversed(facts)), baseline, truths)
    assert again.variant.variant_id == result.variant.variant_id
    assert again.baseline_result.result_id == result.baseline_result.result_id
    assert again.candidate_result.result_id == result.candidate_result.result_id
    assert again.comparison.comparison_id == result.comparison.comparison_id
    assert "NOT_PROMOTED" in result.model_dump_json()
    assert all(
        s not in result.model_dump_json()
        for s in ("success_probability", "priority_score", "promotion_recommendation")
    )


@pytest.mark.parametrize(
    "update",
    [
        {"operation": "EXECUTE_CODE"},
        {"required_permission": "invented_category"},
        {"required_permission": Permission.NETWORK_WRITE},
        {"offline_evaluable": False},
        {"target_reference": "arbitrary.selector"},
        {"threshold": 0.42},
    ],
)
def test_unsupported_operations_parameters_and_targets_rejected(update):
    source, *_ = inputs()
    data = source.model_dump()
    data["content"]["proposal"].update(update)
    with pytest.raises(ValidationError):
        ImprovementCandidate.model_validate(data)


def test_missing_baseline_review_and_unsupported_ground_truth_remain_honest():
    source, facts, spec, plan, baseline, truths = inputs()
    no_baseline = evaluate_unavailable(source, spec, plan, facts)
    assert no_baseline.variant.content.construction_status == "CONSTRUCTIBLE"
    assert no_baseline.variant.content.configuration is None
    assert "BASELINE_UNAVAILABLE" in no_baseline.baseline_result.content.blockers
    assert no_baseline.baseline_result.content.execution_status == "NOT_EXECUTED"
    key = next(iter(truths))
    truths[key] = CoverageGroundTruth(
        status="NOT_MEASURABLE", required_permissions=(), feedback_refs=()
    )
    result = execute_pair(source, spec, plan, facts, baseline, truths)
    metric = next(
        m for m in result.comparison.content.metrics if m.metric == MetricName.MISSED_PATHS
    )
    assert metric.baseline.state == metric.candidate.state == ValueState.NOT_MEASURABLE
    assert metric.delta is None and metric.outcome == "NOT_MEASURABLE"
    assert (
        next(
            a for a in result.comparison.content.acceptance if a.metric == MetricName.MISSED_PATHS
        ).status
        == VerdictState.UNKNOWN
    )
    for kind in (
        CandidateType.PROMPT,
        CandidateType.RULE,
        CandidateType.TOOL_SELECTION_STRATEGY,
        CandidateType.INVESTIGATION_STRATEGY,
    ):
        review, legacy_facts = candidate_for(kind)
        legacy_spec = specify(review, legacy_facts, SplitConfig())
        legacy = evaluate_unavailable(
            review, legacy_spec, make_test_plan(legacy_spec), legacy_facts
        )
        assert legacy.variant.content.construction_status == "VARIANT_NOT_CONSTRUCTIBLE"
        assert legacy.variant.content.structured_offline_change is None


def test_observed_safety_failure_is_not_offset_by_improved_count():
    source, facts, spec, plan, baseline, truths = inputs()
    result = execute_pair(source, spec, plan, facts, baseline, truths)
    c = result.candidate_result.content
    fault_outcomes = tuple(
        CaseOutcome(
            case=o.case,
            status="EXECUTED",
            trace=CoverageTrace(
                configuration_digest=o.trace.configuration_digest,
                selected_permissions=tuple(
                    sorted((*o.trace.selected_permissions, Permission.NETWORK_WRITE))
                ),
                required_permissions=o.trace.required_permissions,
                missing_permissions=o.trace.missing_permissions,
            ),
        )
        for o in c.per_case_outcomes
    )
    assertions = safety(c.cases, fault_outcomes)
    assert (
        next(i for i in assertions if i.invariant == HardInvariant.NO_UNAUTHORIZED_WRITE).status
        == VerdictState.FAIL
    )
    measured = measure(spec.content.metrics, fault_outcomes, assertions)
    fault_content = c.model_copy(
        update={
            "per_case_outcomes": fault_outcomes,
            "invariants": assertions,
            "measurements": measured,
        }
    )
    fault = OfflineEvaluationResult(
        result_id=content_digest(fault_content),
        run_version=result.candidate_result.run_version,
        content=fault_content,
    )
    comparison = compare(spec, result.baseline_result, fault)
    assert (
        next(m for m in comparison.content.metrics if m.metric == MetricName.MISSED_PATHS).outcome
        == "IMPROVED"
    )
    assert (
        next(
            s
            for s in comparison.content.safety
            if s.invariant == HardInvariant.NO_UNAUTHORIZED_WRITE
        ).candidate
        == VerdictState.FAIL
    )
    assert (
        next(
            a for a in comparison.content.acceptance if a.metric == MetricName.UNAUTHORIZED_WRITES
        ).status
        == VerdictState.FAIL
    )
    # This fault trace tests the observer; the durable runner has no injected adapter/callback.
    wrong = (
        fault_outcomes[0].model_copy(update={"case": reference("0" * 64, c.cases[0])}),
    ) + fault_outcomes[1:]
    assert (
        next(
            i
            for i in safety(c.cases, wrong)
            if i.invariant == HardInvariant.NO_CROSS_INCIDENT_ARTIFACT
        ).status
        == VerdictState.FAIL
    )


def test_known_baseline_case_or_split_mismatch_rejected():
    source, facts, spec, plan, baseline, truths = inputs()
    result = execute_pair(source, spec, plan, facts, baseline, truths)
    cfg = CoverageConfiguration(covered_permissions=(Permission.NETWORK_READ,))
    content = BaselineContent(configuration=cfg)
    other = FrozenBaseline(
        baseline_id=content_digest(content),
        baseline_version=content_digest(content),
        content=content,
    )
    newer = execute_pair(source, spec, plan, facts, other, truths)
    with pytest.raises(StoredDataError):
        compare(spec, result.baseline_result, newer.candidate_result)


def test_legacy_feedback_digest_and_new_signed_fact_serialization():
    values = {
        "submission_id": str(UUID(int=1)),
        "incident_id": str(UUID(int=2)),
        "experience_id": "a" * 64,
        "experience_digest": "b" * 64,
        "evaluation_id": "c" * 64,
        "evaluation_digest": "d" * 64,
        "scope": "overall",
        "verdict": "correct",
        "labels": [],
        "note": "",
    }
    request = FeedbackRequest.model_validate(values)
    assert request.model_dump(mode="json") == values
    assert request.digest == hashlib.sha256(canonical_json_object(values).encode()).hexdigest()
    new = FeedbackRequest.model_validate(
        values | {"coverage_expectation": {"required_permissions": ["network_read"]}}
    )
    assert new.digest != request.digest
    assert FeedbackRequest.model_validate_json(new.model_dump_json()) == new
    assert CoverageExpectation(
        required_permissions=(Permission.NETWORK_READ,)
    ).required_permissions == (Permission.NETWORK_READ,)
    with pytest.raises(ValidationError):
        FeedbackRequest.model_validate(
            values
            | {
                "verdict": "inconclusive",
                "coverage_expectation": {"required_permissions": ["network_read"]},
            }
        )
    with pytest.raises(ValidationError):
        CoverageExpectation(required_permissions=(Permission.NETWORK_WRITE,))


@pytest.mark.parametrize(
    "permissions",
    [
        (Permission.SYSTEM_WRITE,),
        (Permission.SYSTEM_READ, Permission.FILE_READ),
        (Permission.NETWORK_READ, Permission.NETWORK_READ),
    ],
)
def test_baseline_configuration_rejects_write_and_noncanonical_paths(permissions):
    with pytest.raises(ValidationError):
        CoverageConfiguration(covered_permissions=permissions)
