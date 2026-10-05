"""Immutable offline planning contracts. No measured results or execution authority."""

from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.improvement_candidates.models import (
    CandidateType,
    DatasetBinding,
    canonical_references,
)
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.state.evidence import UTCTimestamp, utc_now

PLANNER_VERSION = "soc-offline-evaluation-planner:v1"
SPLIT_VERSION = "soc-offline-evaluation-split:v1"


class SplitConfig(Frozen):
    bucket_count: int = Field(default=5, ge=2, strict=True)
    holdout_buckets: int = Field(default=1, ge=1, strict=True)

    @model_validator(mode="after")
    def proportions(self) -> Self:
        if self.holdout_buckets >= self.bucket_count:
            raise ValueError("Development and holdout buckets must both exist")
        return self


class IncidentGroup(Frozen):
    incident_id: UUID
    samples: tuple[ArtifactReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonical(self) -> Self:
        if not canonical_references(self.samples):
            raise ValueError("Canonical incident membership required")
        return self


class PartitionContent(Frozen):
    strategy_version: Literal["soc-offline-evaluation-split:v1"] = SPLIT_VERSION
    dataset: DatasetBinding
    config: SplitConfig
    source_support_refs: tuple[ArtifactReference, ...]
    incident_groups: tuple[IncidentGroup, ...]
    development: tuple[ArtifactReference, ...]
    holdout: tuple[ArtifactReference, ...]
    leakage_status: Literal["RETROSPECTIVE_ONLY"] = "RETROSPECTIVE_ONLY"
    requires_unseen_evaluation_evidence: Literal[True] = True

    @model_validator(mode="after")
    def membership(self) -> Self:
        for refs in (self.source_support_refs, self.development, self.holdout):
            if not canonical_references(refs):
                raise ValueError("Canonical partition references required")
        groups = tuple(str(g.incident_id) for g in self.incident_groups)
        if groups != tuple(sorted(set(groups))):
            raise ValueError("Canonical unique incident groups required")
        members = tuple(r for g in self.incident_groups for r in g.samples)
        if len({r.identity for r in members}) != len(members):
            raise ValueError("Duplicate incident-group sample")
        development = {r.identity: r for r in self.development}
        holdout = {r.identity: r for r in self.holdout}
        if development.keys() & holdout.keys():
            raise ValueError("Partition overlap")
        if {r.identity: r for r in members} != development | holdout:
            raise ValueError("Partition membership does not cover source snapshot")
        if any(development.get(r.identity) != r for r in self.source_support_refs):
            raise ValueError("Candidate support must remain in development")
        for group in self.incident_groups:
            if {r.identity for r in group.samples} & development.keys() and (
                {r.identity for r in group.samples} & holdout.keys()
            ):
                raise ValueError("Cross-partition incident leakage")
        return self


class DatasetPartition(Frozen):
    split_id: Hash
    content: PartitionContent

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.split_id != content_digest(self.content):
            raise ValueError("Split identity mismatch")
        return self


class CandidateBinding(Frozen):
    candidate: ArtifactReference
    candidate_type: CandidateType
    dataset: DatasetBinding
    supporting_pattern_refs: tuple[ArtifactReference, ...]
    supporting_sample_refs: tuple[ArtifactReference, ...]


class BaselineRequirement(Frozen):
    target_component: str
    target_locator: str
    target_version: None = None
    baseline_reference: Literal["UNKNOWN"] = "UNKNOWN"
    requires_versioned_artifact: Literal[True] = True


class VariantKind(StrEnum):
    PROMPT = "candidate_prompt_variant"
    STRATEGY = "candidate_strategy_variant"
    SELECTOR = "candidate_selector_variant"
    RULE = "candidate_rule_variant"


class VariantRequirement(Frozen):
    kind: VariantKind
    artifact_reference: Literal["UNKNOWN"] = "UNKNOWN"
    requires_candidate_variant: Literal[True] = True
    generated_by_planner: Literal[False] = False


class HardInvariant(StrEnum):
    NO_UNAUTHORIZED_WRITE = "no_unauthorized_write"
    NO_APPROVAL_BYPASS = "no_approval_bypass"
    NO_POLICY_BYPASS = "no_policy_bypass"
    NO_PROTECTED_STATE_MUTATION = "no_protected_incident_state_mutation"
    NO_FABRICATED_EVIDENCE = "no_fabricated_evidence"
    NO_CROSS_INCIDENT_ARTIFACT = "no_cross_incident_artifact_use"
    NO_CONFIRMATION_REPLAY = "no_confirmation_replay"
    NO_UNCERTAIN_AUTO_RETRY = "no_uncertain_automatic_retry"
    NO_TOOL_OUTSIDE_SANDBOX = "no_tool_execution_outside_evaluation_sandbox"
    NO_PRODUCTION_MUTATION = "no_production_runtime_mutation"


class ProhibitedSideEffect(StrEnum):
    PROMPT_MUTATION = "runtime_prompt_mutation"
    STRATEGY_MUTATION = "runtime_strategy_mutation"
    POLICY_MUTATION = "policy_mutation"
    RULE_MUTATION = "runtime_rule_mutation"
    MODEL_MUTATION = "model_mutation"
    REGISTRY_MUTATION = "registry_mutation"
    INCIDENT_MUTATION = "protected_incident_mutation"
    APPROVAL_CREATION = "approval_creation"
    PLANNER_TOOL_EXECUTION = "planner_tool_execution"
    LIVE_RESPONSE = "live_response_execution"
    DEPLOYMENT = "deployment"
    PROMOTION = "candidate_promotion"


class SandboxRequirement(Frozen):
    mode: Literal["OFFLINE_SANDBOX"] = "OFFLINE_SANDBOX"
    mock_or_sandbox_external_tools: Literal[True] = True
    deterministic_versioned_inputs: Literal[True] = True
    no_production_side_effects: Literal[True] = True
    no_real_account_or_network_modification: Literal[True] = True
    no_live_response_execution: Literal[True] = True


class MetricName(StrEnum):
    EVALUATED_SAMPLES = "evaluated_sample_count"
    GOVERNANCE_VIOLATIONS = "governance_violation_count"
    UNAUTHORIZED_WRITES = "unauthorized_write_attempt_count"
    PROTECTED_MUTATIONS = "protected_state_mutation_count"
    SCHEMA_VALID = "schema_valid_count"
    SCHEMA_VIOLATIONS = "output_schema_violation_count"
    UNSUPPORTED_ASSERTIONS = "unsupported_assertion_count"
    LABEL_OUTCOME_MISMATCH = "human_label_associated_outcome_mismatch_count"
    FP_OUTCOME_MISMATCH = "fp_associated_outcome_mismatch_count"
    FN_OUTCOME_MISMATCH = "fn_associated_outcome_mismatch_count"
    INVESTIGATION_STEPS = "investigation_step_count"
    MISSED_PATHS = "missed_investigation_path_count"
    UNNECESSARY_PATHS = "unnecessary_investigation_path_count"
    PROHIBITED_SELECTIONS = "prohibited_tool_selection_count"
    SELECTED_READ_ONLY = "selected_read_only_tool_count"
    SELECTED_WRITE = "selected_write_tool_count"
    UNNECESSARY_TOOL_CALLS = "unnecessary_tool_call_count"
    POLICY_DENIALS = "policy_denial_count"
    RULE_DECISION_MISMATCH = "rule_decision_mismatch_count"
    EXECUTION_ATTEMPTS = "execution_attempted_count"
    UNCERTAIN_RETRIES = "automatic_uncertain_retry_count"


class ObservationKind(StrEnum):
    RUN_TRACE = "sandbox_run_trace"
    OUTPUT_SCHEMA = "output_schema_validation_record"
    TOOL_TRACE = "sandbox_tool_selection_trace"
    GOVERNANCE_ASSERTIONS = "governance_assertion_records"
    HUMAN_RUBRIC = "frozen_rubric_and_independent_comparative_adjudication"
    RULE_EXPECTATIONS = "versioned_rule_expectations_and_decision_records"


class MeasurementState(StrEnum):
    UNKNOWN = "UNKNOWN"
    NOT_MEASURABLE = "NOT_MEASURABLE_ON_CURRENT_DATASET"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class MetricDefinition(Frozen):
    name: MetricName
    current_state: MeasurementState = MeasurementState.UNKNOWN
    required_observation: ObservationKind
    counting_rule: str = Field(min_length=1, max_length=1000)
    # This is a definition, not a measured numeric value.
    measure_after_evidence_available: Literal[True] = True


class AcceptanceCriterion(Frozen):
    metric: MetricName
    operator: Literal["EQUAL_ZERO", "NOT_GREATER_THAN_BASELINE", "COVERS_BOUND_HOLDOUT"]
    unknown_handling: Literal["BLOCK"] = "BLOCK"
    requires_baseline_and_candidate_observations: Literal[True] = True


class RequiredEvidence(StrEnum):
    BASELINE_ARTIFACT = "versioned_baseline_artifact_with_digest"
    CANDIDATE_VARIANT = "versioned_candidate_variant_with_digest"
    SANDBOX_FIXTURES = "versioned_privacy_reviewed_sandbox_fixtures"
    RUN_TRACES = "baseline_and_candidate_sandbox_traces"
    MEASUREMENTS = "traceable_metric_observations"
    INVARIANT_RECORDS = "all_hard_invariant_assertion_records"
    RUBRIC = "frozen_label_rubric_and_comparative_adjudication"
    UNSEEN_PROVENANCE = "independent_unseen_evaluation_provenance"


class PlanningBlocker(StrEnum):
    NO_HOLDOUT = "no_holdout_samples"
    BASELINE_UNKNOWN = "baseline_artifact_unknown"
    VARIANT_REQUIRED = "candidate_variant_required"
    RETROSPECTIVE_SOURCE = "source_dataset_already_used_for_proposal"
    OBSERVATIONS_REQUIRED = "future_measurement_evidence_required"


class SpecificationContent(Frozen):
    schema_version: Literal["offline-evaluation-specification:v1"] = (
        "offline-evaluation-specification:v1"
    )
    planner_version: Literal["soc-offline-evaluation-planner:v1"] = PLANNER_VERSION
    binding: CandidateBinding
    evaluation_mode: Literal["OFFLINE_SANDBOX"] = "OFFLINE_SANDBOX"
    baseline: BaselineRequirement
    variant: VariantRequirement
    partition: DatasetPartition
    metrics: tuple[MetricDefinition, ...]
    acceptance_criteria: tuple[AcceptanceCriterion, ...]
    regression_invariants: tuple[HardInvariant, ...]
    governance_invariants: tuple[HardInvariant, ...]
    prohibited_side_effects: tuple[ProhibitedSideEffect, ...]
    required_evidence: tuple[RequiredEvidence, ...]
    environment: SandboxRequirement
    blockers: tuple[PlanningBlocker, ...]
    requires_all_hard_invariants: Literal[True] = True
    hard_invariants_precede_performance: Literal[True] = True
    require_nonempty_complete_holdout: Literal[True] = True
    readiness: Literal["BLOCKED"] = "BLOCKED"
    authority: Literal["OFFLINE_ADVISORY"] = "OFFLINE_ADVISORY"

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.binding.dataset != self.partition.content.dataset or (
            self.binding.supporting_sample_refs != self.partition.content.source_support_refs
        ):
            raise ValueError("Specification/split source mismatch")
        names = tuple(m.name for m in self.metrics)
        if names != tuple(sorted(set(names))):
            raise ValueError("Canonical unique metrics required")
        if any(c.metric not in names for c in self.acceptance_criteria):
            raise ValueError("Acceptance criterion needs a defined metric")
        if self.regression_invariants != tuple(sorted(HardInvariant)) or (
            self.governance_invariants != tuple(sorted(HardInvariant))
        ):
            raise ValueError("All hard invariants are mandatory")
        if self.prohibited_side_effects != tuple(sorted(ProhibitedSideEffect)):
            raise ValueError("All protected side effects are prohibited")
        if not self.partition.content.holdout and PlanningBlocker.NO_HOLDOUT not in self.blockers:
            raise ValueError("Empty holdout must be explicit")
        return self


class EvaluationSpecification(Frozen):
    specification_id: Hash
    specification_version: Hash
    content: SpecificationContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if not self.specification_id == self.specification_version == content_digest(self.content):
            raise ValueError("Specification identity mismatch")
        return self


class TestCaseKind(StrEnum):
    VALIDATE_BINDINGS = "validate_pinned_input_bindings"
    FREEZE_ARTIFACTS = "require_frozen_baseline_and_variant"
    PREPARE_FIXTURES = "require_versioned_sandbox_fixtures"
    BASELINE_REPLAY = "plan_baseline_holdout_replay"
    CANDIDATE_REPLAY = "plan_candidate_holdout_replay"
    COLLECT_MEASUREMENTS = "require_observations_and_adjudication"
    ASSERT_INVARIANTS = "assert_all_hard_invariants"
    COMPARE_CRITERIA = "compare_baseline_relative_criteria"


class PlannedTestCase(Frozen):
    position: int = Field(ge=1, strict=True)
    kind: TestCaseKind
    input_subset: Literal["BOUND_ARTIFACTS", "HOLDOUT", "HOLDOUT_AND_SAFETY_FIXTURES"]
    expected_measurements: tuple[MetricName, ...]
    safety_assertions: tuple[HardInvariant, ...]


class TestPlanContent(Frozen):
    schema_version: Literal["candidate-test-plan:v1"] = "candidate-test-plan:v1"
    planner_version: Literal["soc-offline-evaluation-planner:v1"] = PLANNER_VERSION
    specification: ArtifactReference
    binding: CandidateBinding
    split: ArtifactReference
    baseline: BaselineRequirement
    variant: VariantRequirement
    ordered_test_cases: tuple[PlannedTestCase, ...]
    expected_measurements: tuple[MetricDefinition, ...]
    safety_assertions: tuple[HardInvariant, ...]
    environment: SandboxRequirement
    required_evidence: tuple[RequiredEvidence, ...]
    blockers: tuple[PlanningBlocker, ...]
    execution_mode: Literal["OFFLINE"] = "OFFLINE"
    requires_candidate_variant: Literal[True] = True
    authority: Literal["OFFLINE_ADVISORY"] = "OFFLINE_ADVISORY"
    status: Literal["PLANNED_NOT_EXECUTED"] = "PLANNED_NOT_EXECUTED"

    @model_validator(mode="after")
    def order(self) -> Self:
        if tuple(t.position for t in self.ordered_test_cases) != tuple(
            range(1, len(self.ordered_test_cases) + 1)
        ):
            raise ValueError("Contiguous ordered test cases required")
        if self.safety_assertions != tuple(sorted(HardInvariant)):
            raise ValueError("All hard assertions required")
        if any(t.safety_assertions != self.safety_assertions for t in self.ordered_test_cases):
            raise ValueError("Test case safety assertions must be preserved")
        return self


class CandidateTestPlan(Frozen):
    plan_id: Hash
    content: TestPlanContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.plan_id != content_digest(self.content):
            raise ValueError("Test plan identity mismatch")
        return self


class PlanningResult(Frozen):
    specification: EvaluationSpecification
    test_plan: CandidateTestPlan
