import pytest
from pydantic import ValidationError
from tests.unit.improvement_candidates.test_analysis import fact
from tests.unit.offline_evaluation.test_planning import candidate_for

from soc_agent.improvement_candidates.models import CandidateType
from soc_agent.offline_comparison.evaluation import (
    compare,
    criterion_result,
    evaluate_unavailable,
    metric_delta,
)
from soc_agent.offline_comparison.models import (
    MetricMeasurement,
    OfflineEvaluationResult,
    ValueState,
    VerdictState,
)
from soc_agent.offline_evaluation.models import AcceptanceCriterion, MetricName, SplitConfig
from soc_agent.offline_evaluation.planning import make_test_plan, specify
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


def artifacts(kind=CandidateType.PROMPT):
    source, supporting = candidate_for(kind)
    facts = supporting + tuple(fact(n) for n in range(3, 23))
    spec = specify(source, facts, SplitConfig(bucket_count=2))
    plan = make_test_plan(spec)
    return source, facts, spec, plan, evaluate_unavailable(source, spec, plan, facts)


@pytest.mark.parametrize("kind", list(CandidateType))
def test_review_only_types_cannot_construct_patch_or_guess_baseline(kind):
    source, facts, spec, plan, result = artifacts(kind)
    v = result.variant
    assert v.content.construction_status == "VARIANT_NOT_CONSTRUCTIBLE"
    assert v.content.structured_offline_change is None
    assert v.content.baseline_reference == "UNKNOWN"
    assert v.content.binding.source.candidate.identity == source.candidate_id
    assert v.content.binding.specification.digest == content_digest(spec.content)
    assert v.content.binding.test_plan.digest == content_digest(plan.content)
    assert v.content.binding.source.dataset == source.content.dataset
    assert spec.content.partition.content.holdout
    b, c = result.baseline_result.content, result.candidate_result.content
    assert b.cases == c.cases
    assert b.metric_definitions == c.metric_definitions == spec.content.metrics
    assert b.invariants == c.invariants
    assert (
        tuple(case.content.facts.sample for case in b.cases)
        == spec.content.partition.content.holdout
    )
    assert all(case.content.facts in facts for case in b.cases)
    assert not set(case.content.facts.sources.incident_id for case in b.cases) & set(
        f.sources.incident_id
        for f in facts
        if f.sample in spec.content.partition.content.development
    )
    assert "BASELINE_UNAVAILABLE" in b.blockers
    assert b.execution_status == c.execution_status == "NOT_EXECUTED"
    assert all(m.value is None for m in b.measurements + c.measurements)
    assert all(i.status == VerdictState.UNKNOWN for i in b.invariants)
    assert all(
        m.delta is None and m.outcome == "NOT_MEASURABLE" for m in result.comparison.content.metrics
    )
    assert all(a.status == VerdictState.UNKNOWN for a in result.comparison.content.acceptance)
    again = evaluate_unavailable(source, spec, plan, tuple(reversed(facts)))
    assert result.variant.content == again.variant.content
    assert result.baseline_result.result_id == again.baseline_result.result_id
    assert result.comparison.comparison_id == again.comparison.comparison_id
    serialized = result.model_dump_json()
    assert all(
        s not in serialized for s in ("priority_score", "success_probability", "exec(", "eval(")
    )
    with pytest.raises(ValidationError):
        type(v).model_validate(
            v.model_dump()
            | {"content": v.content.model_dump() | {"structured_offline_change": "invented"}}
        )


def test_not_measurable_steps_and_fake_success_rejected():
    *_, result = artifacts(CandidateType.INVESTIGATION_STRATEGY)
    steps = next(
        m
        for m in result.candidate_result.content.measurements
        if m.metric == MetricName.INVESTIGATION_STEPS
    )
    assert steps.state == ValueState.NOT_MEASURABLE and steps.value is None
    data = result.candidate_result.model_dump()
    data["content"]["invariants"][0]["status"] = "PASS"
    data["result_id"] = content_digest(
        result.candidate_result.content.model_copy(update={"invariants": ()})
    )
    with pytest.raises(ValidationError):
        OfflineEvaluationResult.model_validate(data)
    with pytest.raises(ValidationError):
        MetricMeasurement(
            metric=MetricName.GOVERNANCE_VIOLATIONS, state=ValueState.UNKNOWN, value=0
        )


@pytest.mark.parametrize("change", ["split", "candidate", "cases", "metrics"])
def test_apples_to_apples_mismatch_rejected(change):
    _, _, spec, _, result = artifacts()
    c = result.candidate_result
    if change in ("split", "candidate"):
        binding = c.content.binding
        if change == "split":
            binding = binding.model_copy(
                update={"split": binding.split.model_copy(update={"digest": "0" * 64})}
            )
        else:
            binding = binding.model_copy(
                update={
                    "source": binding.source.model_copy(
                        update={
                            "candidate": binding.source.candidate.model_copy(
                                update={"digest": "0" * 64}
                            )
                        }
                    )
                }
            )
        content = c.content.model_copy(
            update={"binding": binding, "cases": (), "per_case_outcomes": ()}
        )
    elif change == "cases":
        content = c.content.model_copy(update={"cases": (), "per_case_outcomes": ()})
    else:
        content = c.content.model_copy(
            update={
                "metric_definitions": c.content.metric_definitions[:-1],
                "measurements": c.content.measurements[:-1],
            }
        )
    forged = c.model_copy(update={"content": content, "result_id": content_digest(content)})
    with pytest.raises((StoredDataError, ValidationError)):
        compare(spec, result.baseline_result, forged)


@pytest.mark.parametrize(
    "baseline,candidate,outcome,delta",
    [
        (4, 2, "IMPROVED", -2),
        (2, 4, "REGRESSED", 2),
        (2, 2, "UNCHANGED", 0),
        (None, 0, "NOT_MEASURABLE", None),
    ],
)
def test_count_delta_and_baseline_relative_acceptance(baseline, candidate, outcome, delta):
    def measured(value):
        return MetricMeasurement(
            metric=MetricName.FP_OUTCOME_MISMATCH,
            state=ValueState.UNKNOWN if value is None else ValueState.MEASURED,
            value=value,
        )

    b, c = measured(baseline), measured(candidate)
    d = metric_delta(b, c)
    assert (d.delta, d.outcome) == (delta, outcome)
    criterion = AcceptanceCriterion(metric=b.metric, operator="NOT_GREATER_THAN_BASELINE")
    status = criterion_result(criterion, b, c, 2).status
    assert status == (
        VerdictState.UNKNOWN
        if baseline is None
        else VerdictState.PASS
        if candidate <= baseline
        else VerdictState.FAIL
    )


@pytest.mark.parametrize(
    "value,status", [(0, VerdictState.PASS), (1, VerdictState.FAIL), (None, VerdictState.UNKNOWN)]
)
def test_safety_acceptance_never_treats_unknown_as_pass(value, status):
    metric = MetricMeasurement(
        metric=MetricName.UNAUTHORIZED_WRITES,
        state=ValueState.UNKNOWN if value is None else ValueState.MEASURED,
        value=value,
    )
    criterion = AcceptanceCriterion(metric=metric.metric, operator="EQUAL_ZERO")
    assert criterion_result(criterion, metric, metric, 2).status == status
