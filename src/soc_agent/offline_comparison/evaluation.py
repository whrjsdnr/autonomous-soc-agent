"""Shared comparison and honest unavailable evaluation; no external execution or LLMs."""

from pydantic import BaseModel

from soc_agent.improvement_candidates.models import ImprovementCandidate, SampleFacts
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.offline_comparison.coverage_models import FrozenBaseline
from soc_agent.offline_comparison.execution import build_variant
from soc_agent.offline_comparison.models import (
    CaseContent,
    CaseOutcome,
    ComparisonContent,
    CriterionResult,
    EvaluationArtifacts,
    EvaluationBinding,
    EvaluationCase,
    InvariantResult,
    MetricDelta,
    MetricMeasurement,
    OfflineComparison,
    OfflineEvaluationResult,
    ResultContent,
    SafetyComparison,
    ValueState,
    VerdictState,
)
from soc_agent.offline_evaluation.models import (
    AcceptanceCriterion,
    CandidateTestPlan,
    EvaluationSpecification,
    HardInvariant,
    MeasurementState,
    MetricName,
)
from soc_agent.offline_evaluation.planning import make_test_plan, specify
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


def reference(identity: str, content: BaseModel) -> ArtifactReference:
    return ArtifactReference(identity=identity, digest=content_digest(content))


def metric_delta(baseline: MetricMeasurement, candidate: MetricMeasurement) -> MetricDelta:
    baseline = MetricMeasurement.model_validate(baseline.model_dump())
    candidate = MetricMeasurement.model_validate(candidate.model_dump())
    if baseline.metric != candidate.metric:
        raise StoredDataError("Comparison metric mismatch")
    delta = None
    outcome = "NOT_MEASURABLE"
    if baseline.value is not None and candidate.value is not None:
        delta = candidate.value - baseline.value
        # Counts of evaluated/valid/read-only observations are coverage, not failure counts.
        if baseline.metric in (
            MetricName.EVALUATED_SAMPLES,
            MetricName.SCHEMA_VALID,
            MetricName.SELECTED_READ_ONLY,
            MetricName.INVESTIGATION_STEPS,
            MetricName.POLICY_DENIALS,
            MetricName.EXECUTION_ATTEMPTS,
            MetricName.SELECTED_WRITE,
        ):
            outcome = "UNCHANGED" if delta == 0 else "NOT_MEASURABLE"
        else:
            outcome = "UNCHANGED" if delta == 0 else "IMPROVED" if delta < 0 else "REGRESSED"
    return MetricDelta(
        metric=baseline.metric, baseline=baseline, candidate=candidate, delta=delta, outcome=outcome
    )


def criterion_result(
    criterion: AcceptanceCriterion,
    baseline: MetricMeasurement,
    candidate: MetricMeasurement,
    holdout_count: int,
) -> CriterionResult:
    if criterion.metric != baseline.metric or criterion.metric != candidate.metric:
        raise StoredDataError("Acceptance metric mismatch")
    baseline = MetricMeasurement.model_validate(baseline.model_dump())
    candidate = MetricMeasurement.model_validate(candidate.model_dump())
    status = VerdictState.UNKNOWN
    if baseline.value is not None and candidate.value is not None:
        if criterion.operator == "EQUAL_ZERO":
            passed = baseline.value == candidate.value == 0
        elif criterion.operator == "NOT_GREATER_THAN_BASELINE":
            passed = candidate.value <= baseline.value
        else:
            passed = holdout_count > 0 and baseline.value == candidate.value == holdout_count
        status = VerdictState.PASS if passed else VerdictState.FAIL
    return CriterionResult(metric=criterion.metric, operator=criterion.operator, status=status)


def compare(
    specification: EvaluationSpecification,
    baseline: OfflineEvaluationResult,
    candidate: OfflineEvaluationResult,
) -> OfflineComparison:
    # Revalidate even when callers use Pydantic model_copy/model_construct.
    specification = EvaluationSpecification.model_validate(specification.model_dump())
    baseline = OfflineEvaluationResult.model_validate(baseline.model_dump())
    candidate = OfflineEvaluationResult.model_validate(candidate.model_dump())
    b, c = baseline.content, candidate.content
    s = specification.content
    if (
        b.arm != "BASELINE"
        or c.arm != "CANDIDATE"
        or (
            b.binding != c.binding
            or b.binding.source != s.binding
            or b.binding.specification != reference(specification.specification_id, s)
            or b.binding.split != reference(s.partition.split_id, s.partition.content)
            or b.cases != c.cases
            or b.metric_definitions != c.metric_definitions
            or b.metric_definitions != s.metrics
            or b.execution_status != c.execution_status
            or b.evaluator_version != c.evaluator_version
            or b.sandbox != c.sandbox
            or tuple(i.invariant for i in b.invariants) != tuple(i.invariant for i in c.invariants)
            or tuple(case.content.facts.sample for case in b.cases) != s.partition.content.holdout
        )
    ):
        raise StoredDataError("Baseline/candidate apples-to-apples binding mismatch")
    content = ComparisonContent(
        binding=b.binding,
        baseline_result=reference(baseline.result_id, b),
        candidate_result=reference(candidate.result_id, c),
        metrics=tuple(
            metric_delta(x, y) for x, y in zip(b.measurements, c.measurements, strict=True)
        ),
        safety=tuple(
            SafetyComparison(invariant=x.invariant, baseline=x.status, candidate=y.status)
            for x, y in zip(b.invariants, c.invariants, strict=True)
        ),
        acceptance=tuple(
            criterion_result(
                criterion,
                next(m for m in b.measurements if m.metric == criterion.metric),
                next(m for m in c.measurements if m.metric == criterion.metric),
                len(b.cases),
            )
            for criterion in s.acceptance_criteria
        ),
    )
    return OfflineComparison(comparison_id=content_digest(content), content=content)


def evaluate_unavailable(
    source: ImprovementCandidate,
    specification: EvaluationSpecification,
    plan: CandidateTestPlan,
    facts: tuple[SampleFacts, ...],
    *,
    baseline: FrozenBaseline | None = None,
) -> EvaluationArtifacts:
    source = ImprovementCandidate.model_validate(source.model_dump())
    specification = EvaluationSpecification.model_validate(specification.model_dump())
    plan = CandidateTestPlan.model_validate(plan.model_dump())
    s = specification.content
    if specify(source, facts, s.partition.content.config).content != s or (
        make_test_plan(specification).content != plan.content
    ):
        raise StoredDataError("Candidate/specification/plan/split mismatch")
    binding = EvaluationBinding(
        frozen_baseline=reference(baseline.baseline_id, baseline.content) if baseline else None,
        source=s.binding,
        specification=reference(specification.specification_id, s),
        test_plan=reference(plan.plan_id, plan.content),
        split=reference(s.partition.split_id, s.partition.content),
    )
    variant = build_variant(source, binding, baseline)
    v = variant.content
    members = {f.sample.identity: f for f in facts}
    cases = []
    for ref in s.partition.content.holdout:
        fact = members.get(ref.identity)
        if fact is None or fact.sample != ref:
            raise StoredDataError("Missing or forged holdout sample")
        context = CaseContent(binding=binding, facts=fact, applicable_metrics=s.metrics)
        cases.append(EvaluationCase(case_id=content_digest(context), content=context))
    measurements = tuple(
        MetricMeasurement(
            metric=m.name,
            state=ValueState.NOT_MEASURABLE
            if m.current_state == MeasurementState.NOT_MEASURABLE
            else ValueState.NOT_APPLICABLE
            if m.current_state == MeasurementState.NOT_APPLICABLE
            else ValueState.UNKNOWN,
        )
        for m in s.metrics
    )
    blockers = {str(b) for b in s.blockers} | {"SANDBOX_FIXTURES_UNAVAILABLE"}
    if baseline is None:
        blockers.add("BASELINE_UNAVAILABLE")
    else:
        blockers.discard("baseline_artifact_unknown")
    if v.construction_status == "VARIANT_NOT_CONSTRUCTIBLE":
        blockers.add("VARIANT_NOT_CONSTRUCTIBLE")
    if not s.partition.content.holdout:
        blockers.add("NO_HOLDOUT")
    blockers = tuple(sorted(blockers))
    results = []
    for arm in ("BASELINE", "CANDIDATE"):
        content = ResultContent(
            binding=binding,
            baseline_reference=binding.frozen_baseline or "UNKNOWN",
            arm=arm,
            variant=reference(variant.variant_id, v) if arm == "CANDIDATE" else None,
            cases=tuple(cases),
            per_case_outcomes=tuple(
                CaseOutcome(case=reference(case.case_id, case)) for case in cases
            ),
            metric_definitions=s.metrics,
            measurements=measurements,
            invariants=tuple(
                InvariantResult(invariant=i, status=VerdictState.UNKNOWN)
                for i in sorted(HardInvariant)
            ),
            blockers=blockers,
        )
        results.append(OfflineEvaluationResult(result_id=content_digest(content), content=content))
    baseline, candidate = results
    return EvaluationArtifacts(
        variant=variant,
        baseline_result=baseline,
        candidate_result=candidate,
        comparison=compare(specification, baseline, candidate),
    )
