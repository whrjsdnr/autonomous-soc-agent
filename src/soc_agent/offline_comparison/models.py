"""Frozen, reference-first offline evaluation artifacts with explicit unknowns."""

from enum import StrEnum
from typing import ClassVar, Literal, Self, cast

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from soc_agent.improvement_candidates.models import CandidateType, CoverageProposal, SampleFacts
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.offline_comparison.coverage_models import (
    CoverageConfiguration,
    CoverageGroundTruth,
    CoverageTrace,
)
from soc_agent.offline_evaluation.models import (
    CandidateBinding,
    HardInvariant,
    MetricDefinition,
    MetricName,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.state.evidence import UTCTimestamp, utc_now

BUILDER_VERSION = "soc-offline-candidate-variant-builder:v1"
EVALUATOR_VERSION = "soc-offline-candidate-evaluator:v1"
COMPARATOR_VERSION = "soc-baseline-candidate-comparator:v1"
EXEC_BUILDER_VERSION = "soc-offline-candidate-variant-builder:v2"
EXEC_EVALUATOR_VERSION = "soc-offline-candidate-evaluator:v2"


class VerdictState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ValueState(StrEnum):
    MEASURED = "MEASURED"
    UNKNOWN = "UNKNOWN"
    NOT_MEASURABLE = "NOT_MEASURABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CompatibleFrozen(Frozen):
    """Omit only new absent fields so existing v1 durable hashes remain exact."""

    legacy_omitted: ClassVar[tuple[str, ...]] = ()

    @model_serializer(mode="wrap")
    def legacy_serialization(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        value = cast(dict[str, object], handler(self))
        for name in self.legacy_omitted:
            if getattr(self, name) is None:
                value.pop(name, None)
        return value


class EvaluationBinding(CompatibleFrozen):
    legacy_omitted = ("frozen_baseline",)
    frozen_baseline: ArtifactReference | None = None
    source: CandidateBinding
    specification: ArtifactReference
    test_plan: ArtifactReference
    split: ArtifactReference


class VariantContent(CompatibleFrozen):
    legacy_omitted = ("configuration",)
    configuration: CoverageConfiguration | None = None
    builder_version: Literal[
        "soc-offline-candidate-variant-builder:v1", "soc-offline-candidate-variant-builder:v2"
    ] = BUILDER_VERSION
    binding: EvaluationBinding
    candidate_type: CandidateType
    target_component: str
    baseline_reference: Literal["UNKNOWN"] | ArtifactReference = "UNKNOWN"
    construction_status: Literal["VARIANT_NOT_CONSTRUCTIBLE", "CONSTRUCTIBLE"] = (
        "VARIANT_NOT_CONSTRUCTIBLE"
    )
    construction_reason: Literal[
        "REVIEW_ONLY_WITHOUT_EXECUTABLE_CHANGE", "EXPLICIT_ALLOWLISTED_COVERAGE"
    ] = "REVIEW_ONLY_WITHOUT_EXECUTABLE_CHANGE"
    structured_offline_change: CoverageProposal | None = None
    authority: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"
    promotion_status: Literal["NOT_PROMOTED"] = "NOT_PROMOTED"
    runtime_authority: Literal["NOT_RUNTIME_AUTHORITY"] = "NOT_RUNTIME_AUTHORITY"

    @model_validator(mode="after")
    def construction(self) -> Self:
        supported = self.construction_status == "CONSTRUCTIBLE"
        if (
            supported != (self.structured_offline_change is not None)
            or supported != (self.builder_version == EXEC_BUILDER_VERSION)
            or supported != (self.construction_reason == "EXPLICIT_ALLOWLISTED_COVERAGE")
        ):
            raise ValueError("Variant construction contract mismatch")
        if self.baseline_reference != (self.binding.frozen_baseline or "UNKNOWN"):
            raise ValueError("Variant frozen baseline mismatch")
        if self.configuration is not None and (
            not supported or self.binding.frozen_baseline is None
        ):
            raise ValueError("Configuration requires explicit baseline and structured proposal")
        return self


class OfflineCandidateVariant(Frozen):
    variant_id: Hash
    variant_version: Hash
    content: VariantContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if not self.variant_id == self.variant_version == content_digest(self.content):
            raise ValueError("Variant identity mismatch")
        return self


class CaseContent(CompatibleFrozen):
    legacy_omitted = ("coverage",)
    coverage: CoverageGroundTruth | None = None
    binding: EvaluationBinding
    facts: SampleFacts
    applicable_metrics: tuple[MetricDefinition, ...]
    context_status: Literal[
        "REFERENCES_ONLY_FIXTURE_UNAVAILABLE", "FROZEN_PERMISSION_COVERAGE_INPUT"
    ] = "REFERENCES_ONLY_FIXTURE_UNAVAILABLE"

    @model_validator(mode="after")
    def ground_truth(self) -> Self:
        if (self.coverage is not None) != (
            self.context_status == "FROZEN_PERMISSION_COVERAGE_INPUT"
        ):
            raise ValueError("Case context status mismatch")
        if self.coverage is not None and not {
            (r.identity, r.digest) for r in self.coverage.feedback_refs
        } <= {(r.identity, r.digest) for r in self.facts.sources.feedback}:
            raise ValueError("Ground truth must come from contributing feedback")
        return self


class EvaluationCase(Frozen):
    case_id: Hash
    content: CaseContent

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.case_id != content_digest(self.content):
            raise ValueError("Case identity mismatch")
        return self


class MetricMeasurement(Frozen):
    metric: MetricName
    state: ValueState
    value: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def unknown(self) -> Self:
        if (self.state == ValueState.MEASURED) != (self.value is not None):
            raise ValueError("Measured counts need values; unknown counts have no value")
        return self


class InvariantResult(CompatibleFrozen):
    legacy_omitted = ("basis",)
    basis: (
        Literal[
            "ADAPTER_HAS_NO_PRODUCTION_CAPABILITY",
            "BOUND_CASE_TRACE_CHECK",
            "OBSERVED_PERMISSION_SELECTION",
            "DOWNSTREAM_GATES_NOT_EXERCISED",
        ]
        | None
    ) = None
    invariant: HardInvariant
    status: VerdictState


class CaseOutcome(CompatibleFrozen):
    legacy_omitted = ("trace",)
    trace: CoverageTrace | None = None
    case: ArtifactReference
    status: Literal["NOT_EXECUTED", "EXECUTED"] = "NOT_EXECUTED"


class ResultContent(Frozen):
    evaluator_version: Literal[
        "soc-offline-candidate-evaluator:v1", "soc-offline-candidate-evaluator:v2"
    ] = EVALUATOR_VERSION
    binding: EvaluationBinding
    arm: Literal["BASELINE", "CANDIDATE"]
    baseline_reference: Literal["UNKNOWN"] | ArtifactReference = "UNKNOWN"
    variant: ArtifactReference | None
    cases: tuple[EvaluationCase, ...]
    per_case_outcomes: tuple[CaseOutcome, ...]
    metric_definitions: tuple[MetricDefinition, ...]
    measurements: tuple[MetricMeasurement, ...]
    invariants: tuple[InvariantResult, ...]
    blockers: tuple[str, ...]
    execution_status: Literal["NOT_EXECUTED", "EXECUTED"] = "NOT_EXECUTED"
    sandbox: Literal["OFFLINE_NO_EXECUTION", "OFFLINE_PERMISSION_COVERAGE"] = "OFFLINE_NO_EXECUTION"
    authority: Literal["OFFLINE_ADVISORY"] = "OFFLINE_ADVISORY"

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.baseline_reference != (self.binding.frozen_baseline or "UNKNOWN"):
            raise ValueError("Result frozen baseline mismatch")
        if any(case.content.applicable_metrics != self.metric_definitions for case in self.cases):
            raise ValueError("Frozen case metric definitions mismatch")
        if (self.arm == "CANDIDATE") != (self.variant is not None):
            raise ValueError("Candidate result needs exactly its variant")
        if tuple(m.metric for m in self.measurements) != tuple(
            m.name for m in self.metric_definitions
        ):
            raise ValueError("Result metric definitions mismatch")
        if self.execution_status == "NOT_EXECUTED" and any(
            m.state == ValueState.MEASURED for m in self.measurements
        ):
            raise ValueError("Unexecuted results cannot carry measurements")
        if tuple(i.invariant for i in self.invariants) != tuple(sorted(HardInvariant)):
            raise ValueError("Every hard invariant must be recorded")
        if self.execution_status == "NOT_EXECUTED" and any(
            i.status != VerdictState.UNKNOWN for i in self.invariants
        ):
            raise ValueError("Unexecuted safety is unknown")
        executed = self.execution_status == "EXECUTED"
        if executed:
            if self.evaluator_version != EXEC_EVALUATOR_VERSION or (
                self.binding.frozen_baseline is None
                or self.baseline_reference != self.binding.frozen_baseline
                or self.sandbox != "OFFLINE_PERMISSION_COVERAGE"
                or not self.cases
            ):
                raise ValueError(
                    "Executed results require frozen baseline and nonempty offline cases"
                )
            if any(i.status != VerdictState.UNKNOWN and i.basis is None for i in self.invariants):
                raise ValueError("Observed safety decisions require explicit evidence basis")
        elif self.sandbox != "OFFLINE_NO_EXECUTION":
            raise ValueError("Unexecuted results cannot claim sandbox execution")
        if any(
            (o.status == "EXECUTED") != executed or (o.trace is not None) != executed
            for o in self.per_case_outcomes
        ):
            raise ValueError("Per-case execution status mismatch")
        refs = tuple(
            ArtifactReference(identity=c.case_id, digest=content_digest(c)) for c in self.cases
        )
        if tuple(o.case for o in self.per_case_outcomes) != refs:
            raise ValueError("Per-case outcomes mismatch")
        samples = tuple(c.content.facts.sample.identity for c in self.cases)
        if samples != tuple(sorted(set(samples))):
            raise ValueError("Canonical unique evaluation cases required")
        if any(c.content.binding != self.binding for c in self.cases):
            raise ValueError("Cross-evaluation case")
        return self


class OfflineEvaluationResult(Frozen):
    result_id: Hash
    run_version: Literal[
        "soc-offline-candidate-evaluator:v1", "soc-offline-candidate-evaluator:v2"
    ] = EVALUATOR_VERSION
    content: ResultContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.run_version != self.content.evaluator_version:
            raise ValueError("Result evaluator version mismatch")
        if self.result_id != content_digest(self.content):
            raise ValueError("Result identity mismatch")
        return self


class MetricDelta(Frozen):
    metric: MetricName
    baseline: MetricMeasurement
    candidate: MetricMeasurement
    delta: int | None = Field(default=None, strict=True)
    outcome: Literal["IMPROVED", "UNCHANGED", "REGRESSED", "NOT_MEASURABLE"]


class SafetyComparison(Frozen):
    invariant: HardInvariant
    baseline: VerdictState
    candidate: VerdictState


class CriterionResult(Frozen):
    metric: MetricName
    operator: Literal["EQUAL_ZERO", "NOT_GREATER_THAN_BASELINE", "COVERS_BOUND_HOLDOUT"]
    status: VerdictState


class ComparisonContent(Frozen):
    comparator_version: Literal["soc-baseline-candidate-comparator:v1"] = COMPARATOR_VERSION
    binding: EvaluationBinding
    baseline_result: ArtifactReference
    candidate_result: ArtifactReference
    metrics: tuple[MetricDelta, ...]
    safety: tuple[SafetyComparison, ...]
    acceptance: tuple[CriterionResult, ...]
    authority: Literal["OFFLINE_ADVISORY"] = "OFFLINE_ADVISORY"


class OfflineComparison(Frozen):
    comparison_id: Hash
    content: ComparisonContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.comparison_id != content_digest(self.content):
            raise ValueError("Comparison identity mismatch")
        return self


class EvaluationArtifacts(Frozen):
    variant: OfflineCandidateVariant
    baseline_result: OfflineEvaluationResult
    candidate_result: OfflineEvaluationResult
    comparison: OfflineComparison
