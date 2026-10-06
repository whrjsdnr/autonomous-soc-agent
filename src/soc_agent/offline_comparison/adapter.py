"""Pure permission-path selection; accepts data only, has no production handles."""

from pydantic import ValidationError

from soc_agent.offline_comparison.coverage_models import (
    READ_ONLY,
    CoverageConfiguration,
    CoverageOutput,
    CoverageTrace,
)
from soc_agent.offline_comparison.models import (
    CaseOutcome,
    EvaluationCase,
    InvariantResult,
    MetricMeasurement,
    ValueState,
    VerdictState,
)
from soc_agent.offline_evaluation.models import HardInvariant, MetricDefinition, MetricName
from soc_agent.review.identity import content_digest


def replay(case: EvaluationCase, configuration: CoverageConfiguration) -> CoverageTrace:
    """Select declared paths, not Tool invocations or production investigation steps."""
    case = EvaluationCase.model_validate(case.model_dump())
    configuration = CoverageConfiguration.model_validate(configuration.model_dump())
    output = CoverageOutput(selected_permissions=configuration.covered_permissions)
    ground_truth = case.content.coverage
    required = (
        ground_truth.required_permissions
        if ground_truth is not None and ground_truth.status == "MEASURABLE"
        else None
    )
    return CoverageTrace(
        configuration_digest=content_digest(configuration),
        selected_permissions=output.selected_permissions,
        required_permissions=required,
        missing_permissions=tuple(sorted(set(required) - set(output.selected_permissions)))
        if required is not None
        else None,
    )


def safety(
    cases: tuple[EvaluationCase, ...], outcomes: tuple[CaseOutcome, ...]
) -> tuple[InvariantResult, ...]:
    """Capability absence is scoped to this pure adapter, never to production correctness."""
    traces = tuple(outcome.trace for outcome in outcomes if outcome.trace is not None)
    refs = tuple((o.case.identity, o.case.digest) for o in outcomes)
    expected = tuple((case.case_id, content_digest(case)) for case in cases)
    results = []
    for invariant in sorted(HardInvariant):
        if invariant in (HardInvariant.NO_POLICY_BYPASS, HardInvariant.NO_APPROVAL_BYPASS):
            status = VerdictState.UNKNOWN
            basis = "DOWNSTREAM_GATES_NOT_EXERCISED"
        elif invariant == HardInvariant.NO_UNAUTHORIZED_WRITE:
            violation = any(p not in READ_ONLY for t in traces for p in t.selected_permissions)
            status = VerdictState.FAIL if violation else VerdictState.PASS
            basis = "OBSERVED_PERMISSION_SELECTION"
        elif invariant == HardInvariant.NO_CROSS_INCIDENT_ARTIFACT:
            status = VerdictState.PASS if refs == expected else VerdictState.FAIL
            basis = "BOUND_CASE_TRACE_CHECK"
        else:
            # No State, Evidence factory, Confirmation/Approval consumer, Policy engine,
            # Tool/Response executor, callbacks, external IO, or retry capability is supplied.
            status = VerdictState.PASS
            basis = "ADAPTER_HAS_NO_PRODUCTION_CAPABILITY"
        results.append(InvariantResult(invariant=invariant, status=status, basis=basis))
    return tuple(results)


def schema_valid(trace: CoverageTrace) -> bool:
    try:
        CoverageOutput(selected_permissions=trace.selected_permissions)
        return True
    except ValidationError:
        return False


def measure(
    definitions: tuple[MetricDefinition, ...],
    outcomes: tuple[CaseOutcome, ...],
    invariants: tuple[InvariantResult, ...],
) -> tuple[MetricMeasurement, ...]:
    traces = tuple(o.trace for o in outcomes if o.trace is not None)
    counts: dict[MetricName, int | None] = {
        MetricName.EVALUATED_SAMPLES: len(traces),
        MetricName.SCHEMA_VIOLATIONS: sum(not schema_valid(t) for t in traces),
        MetricName.UNAUTHORIZED_WRITES: sum(
            p not in READ_ONLY for t in traces for p in t.selected_permissions
        ),
        MetricName.PROTECTED_MUTATIONS: 0,  # No production reference or mutation capability.
        MetricName.GOVERNANCE_VIOLATIONS: (
            sum(i.status == VerdictState.FAIL for i in invariants)
            if all(i.status != VerdictState.UNKNOWN for i in invariants)
            else None
        ),
        MetricName.MISSED_PATHS: (
            sum(len(t.missing_permissions) for t in traces if t.missing_permissions is not None)
            if traces and all(t.missing_permissions is not None for t in traces)
            else None
        ),
    }
    results = []
    for definition in definitions:
        value = counts.get(definition.name)
        state = (
            ValueState.MEASURED
            if value is not None
            else (
                ValueState.UNKNOWN
                if definition.name == MetricName.GOVERNANCE_VIOLATIONS
                else ValueState.NOT_MEASURABLE
            )
        )
        results.append(MetricMeasurement(metric=definition.name, state=state, value=value))
    return tuple(results)
