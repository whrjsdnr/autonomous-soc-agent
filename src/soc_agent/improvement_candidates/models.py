"""Frozen historical observations and advisory proposals, never execution authority."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from soc_agent.feedback.models import DiagnosticLabel, Verdict
from soc_agent.improvement_dataset.models import (
    ArtifactReference,
    ImprovementSample,
    ObjectiveContext,
    SampleContent,
    SourceSnapshot,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.state.evidence import UTCTimestamp, utc_now
from soc_agent.tools.models import ReadOnlyPermission

ANALYZER_VERSION = "soc-failure-analyzer:v1"
GENERATOR_VERSION = "soc-improvement-candidate-generator:v1"
DECLARATION_VERSION = "soc-offline-coverage-proposal-declaration:v1"


class AnalysisConfig(Frozen):
    minimum_pattern_support: int = Field(default=2, ge=2, strict=True)


class DatasetBinding(Frozen):
    dataset_id: Hash
    dataset_version: Hash
    manifest_digest: Hash

    @model_validator(mode="after")
    def identity(self) -> Self:
        if not self.dataset_id == self.dataset_version == self.manifest_digest:
            raise ValueError("Dataset content identity mismatch")
        return self


class PatternType(StrEnum):
    INCORRECT = "incorrect_pattern"
    FALSE_POSITIVE = "false_positive_pattern"
    FALSE_NEGATIVE = "false_negative_pattern"
    UNNECESSARY_INVESTIGATION = "unnecessary_investigation_pattern"
    MISSED_INVESTIGATION = "missed_investigation_pattern"
    EXECUTION_FAILURE = "execution_failure_pattern"
    EXECUTION_UNCERTAINTY = "execution_uncertainty_pattern"
    RECOVERY = "recovery_pattern"


class SampleFacts(Frozen):
    sample: ArtifactReference
    sources: SourceSnapshot
    verdict: Verdict
    labels: tuple[DiagnosticLabel, ...]
    objective: ObjectiveContext
    recovery_observed: bool
    uncertain_observed: bool
    reconciliation_observed: bool

    @model_validator(mode="after")
    def sample_binding(self) -> Self:
        content = SampleContent(
            sources=self.sources,
            verdict=self.verdict,
            labels=self.labels,
            objective=self.objective,
        )
        sample = ImprovementSample(sample_id=content_digest(content), content=content)
        if self.sample != ArtifactReference(
            identity=sample.sample_id,
            digest=content_digest(sample),
        ):
            raise ValueError("Observed facts do not match the sample reference")
        return self


def canonical_references(refs: tuple[ArtifactReference, ...]) -> bool:
    return tuple(r.identity for r in refs) == tuple(sorted({r.identity for r in refs}))


class PatternContent(Frozen):
    schema_version: Literal["failure-pattern:v1"] = "failure-pattern:v1"
    dataset: DatasetBinding
    analyzer_version: Literal["soc-failure-analyzer:v1"] = ANALYZER_VERSION
    config: AnalysisConfig
    pattern_type: PatternType
    supporting_sample_refs: tuple[ArtifactReference, ...]
    supporting_feedback_refs: tuple[ArtifactReference, ...]
    observed_facts: tuple[SampleFacts, ...]
    occurrence_count: int = Field(ge=2)
    affected_scope: Literal["overall"] = "overall"
    root_cause_status: Literal["UNKNOWN"] = "UNKNOWN"

    @model_validator(mode="after")
    def support(self) -> Self:
        if not canonical_references(self.supporting_sample_refs) or not canonical_references(
            self.supporting_feedback_refs
        ):
            raise ValueError("Canonical unique support required")
        if self.supporting_sample_refs != tuple(f.sample for f in self.observed_facts):
            raise ValueError("Observed facts/sample support mismatch")
        feedback: dict[str, ArtifactReference] = {}
        for fact in self.observed_facts:
            for ref in fact.sources.feedback:
                if ref.identity in feedback and feedback[ref.identity] != ref:
                    raise ValueError("Conflicting feedback support")
                feedback[ref.identity] = ref
        expected = tuple(feedback[key] for key in sorted(feedback))
        if self.supporting_feedback_refs != expected:
            raise ValueError("Feedback support mismatch")
        if self.occurrence_count != len(self.observed_facts):
            raise ValueError("Occurrence count mismatch")
        if self.occurrence_count < self.config.minimum_pattern_support:
            raise ValueError("Insufficient repeated support")
        return self


class FailurePattern(Frozen):
    pattern_id: Hash
    content: PatternContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.pattern_id != content_digest(self.content):
            raise ValueError("Pattern identity mismatch")
        return self

    @property
    def supporting_sample_ids(self) -> tuple[str, ...]:
        return tuple(r.identity for r in self.content.supporting_sample_refs)


class CandidateType(StrEnum):
    PROMPT = "prompt"
    INVESTIGATION_STRATEGY = "investigation_strategy"
    TOOL_SELECTION_STRATEGY = "tool_selection_strategy"
    RULE = "rule"


class ReviewFocus(StrEnum):
    HUMAN_INCORRECT = "human_incorrect_review"
    FALSE_POSITIVE = "false_positive_label_review"
    FALSE_NEGATIVE = "false_negative_label_review"
    UNNECESSARY_INVESTIGATION = "unnecessary_investigation_label_review"
    MISSED_INVESTIGATION = "missed_investigation_label_review"
    EXECUTION_FAILURE = "execution_failure_review"
    EXECUTION_UNCERTAINTY = "execution_uncertainty_review"
    RECOVERY = "recovery_review"


class PromptProposal(Frozen):
    candidate_type: Literal[CandidateType.PROMPT] = CandidateType.PROMPT
    operation: Literal["REVIEW"] = "REVIEW"
    target_component: Literal["assessment"] = "assessment"
    target_reference: Literal["soc_agent.assessment.prompts.SYSTEM_PROMPT"] = (
        "soc_agent.assessment.prompts.SYSTEM_PROMPT"
    )
    target_version: None = None
    focus: ReviewFocus
    proposed_guidance: Literal[
        "Review evidence-grounded assessment guidance against supporting human labels."
    ] = "Review evidence-grounded assessment guidance against supporting human labels."


class InvestigationProposal(Frozen):
    candidate_type: Literal[CandidateType.INVESTIGATION_STRATEGY] = (
        CandidateType.INVESTIGATION_STRATEGY
    )
    operation: Literal["REVIEW"] = "REVIEW"
    target_component: Literal["investigation_planning"] = "investigation_planning"
    target_reference: Literal["soc_agent.planning.models.PlannerInput"] = (
        "soc_agent.planning.models.PlannerInput"
    )
    target_version: None = None
    focus: ReviewFocus
    proposed_coverage_review: Literal[
        "Review investigation coverage and stopping guidance against supporting human labels."
    ] = "Review investigation coverage and stopping guidance against supporting human labels."


class ToolSelectionProposal(Frozen):
    candidate_type: Literal[CandidateType.TOOL_SELECTION_STRATEGY] = (
        CandidateType.TOOL_SELECTION_STRATEGY
    )
    operation: Literal["REVIEW"] = "REVIEW"
    target_component: Literal["investigation_tool_selection"] = "investigation_tool_selection"
    target_reference: Literal["soc_agent.planning.models.ToolCatalogEntry"] = (
        "soc_agent.planning.models.ToolCatalogEntry"
    )
    target_version: None = None
    focus: ReviewFocus
    proposed_constraint_review: Literal[
        "Review read-only catalog coverage; retain schema validation and existing permissions."
    ] = "Review read-only catalog coverage; retain schema validation and existing permissions."


class RuleProposal(Frozen):
    candidate_type: Literal[CandidateType.RULE] = CandidateType.RULE
    operation: Literal["REVIEW"] = "REVIEW"
    target_component: Literal["execution_reliability"] = "execution_reliability"
    target_reference: Literal["soc_agent.execution.durable.store.ExecutionStore"] = (
        "soc_agent.execution.durable.store.ExecutionStore"
    )
    target_version: None = None
    focus: ReviewFocus
    proposed_rule_description: Literal[
        "Review failure and recovery handling; preserve policy, approval and execution boundaries."
    ] = "Review failure and recovery handling; preserve policy, approval and execution boundaries."


class CoverageProposal(Frozen):
    """Caller-declared offline coverage addition, never generated from labels."""

    candidate_type: Literal[CandidateType.INVESTIGATION_STRATEGY] = (
        CandidateType.INVESTIGATION_STRATEGY
    )
    operation: Literal["REQUIRE_READ_ONLY_PERMISSION_COVERAGE"] = (
        "REQUIRE_READ_ONLY_PERMISSION_COVERAGE"
    )
    target_component: Literal["investigation_planning"] = "investigation_planning"
    target_reference: Literal["soc_agent.planning.models.PlannerInput"] = (
        "soc_agent.planning.models.PlannerInput"
    )
    target_version: None = None
    focus: Literal[ReviewFocus.MISSED_INVESTIGATION] = ReviewFocus.MISSED_INVESTIGATION
    required_permission: ReadOnlyPermission
    review_candidate: ArtifactReference
    offline_evaluable: Literal[True] = True


InvestigationProposalContract = Annotated[
    InvestigationProposal | CoverageProposal, Field(discriminator="operation")
]

Proposal = Annotated[
    PromptProposal | InvestigationProposalContract | ToolSelectionProposal | RuleProposal,
    Field(discriminator="candidate_type"),
]


class CandidateContent(Frozen):
    schema_version: Literal["improvement-candidate:v1", "improvement-candidate:v2"] = (
        "improvement-candidate:v1"
    )
    dataset: DatasetBinding
    generator_version: Literal[
        "soc-improvement-candidate-generator:v1", "soc-offline-coverage-proposal-declaration:v1"
    ] = GENERATOR_VERSION
    candidate_type: CandidateType
    failure_pattern_refs: tuple[ArtifactReference, ...] = Field(min_length=1, max_length=1)
    supporting_sample_refs: tuple[ArtifactReference, ...]
    proposal: Proposal
    rationale: str = Field(min_length=1, max_length=1000)
    expected_effect: str = Field(min_length=1, max_length=1000)
    authority: Literal["ADVISORY"] = "ADVISORY"
    status: Literal["PROPOSED"] = "PROPOSED"
    requires_offline_evaluation: Literal[True] = True
    requires_human_approval: Literal[True] = True

    @model_validator(mode="after")
    def structure(self) -> Self:
        executable = isinstance(self.proposal, CoverageProposal)
        if executable != (self.generator_version == DECLARATION_VERSION) or executable != (
            self.schema_version == "improvement-candidate:v2"
        ):
            raise ValueError("Explicit declaration version required for offline coverage proposal")
        if self.candidate_type != self.proposal.candidate_type:
            raise ValueError("Candidate/proposal type mismatch")
        if not self.supporting_sample_refs or not canonical_references(self.supporting_sample_refs):
            raise ValueError("Canonical nonempty candidate support required")
        return self


class ImprovementCandidate(Frozen):
    candidate_id: Hash
    candidate_version: Hash
    content: CandidateContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if not self.candidate_id == self.candidate_version == content_digest(self.content):
            raise ValueError("Candidate identity mismatch")
        return self


class CandidateTypeCount(Frozen):
    candidate_type: CandidateType
    count: int = Field(ge=0)


class ImprovementStatistics(Frozen):
    pattern_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    candidate_type_counts: tuple[CandidateTypeCount, ...]
    # Counts are per pattern, not a sum of independent incidents.
    pattern_support_counts: tuple[tuple[Hash, int], ...]


class ProposalResult(Frozen):
    patterns: tuple[FailurePattern, ...]
    candidates: tuple[ImprovementCandidate, ...]
