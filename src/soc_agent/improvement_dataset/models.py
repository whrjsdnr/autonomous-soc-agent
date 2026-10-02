"""Content-addressed offline snapshots; no runtime or governance authority."""

from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.experience.models import GovernanceOutcome, HistoricalOutcome
from soc_agent.feedback.models import DiagnosticLabel, Verdict
from soc_agent.investigation.runtime.models import WorkflowFailure, WorkflowStep
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.state.evidence import UTCTimestamp, utc_now

BUILDER_VERSION = "soc-improvement-dataset-builder:v1"
ELIGIBILITY_VERSION = "soc-improvement-eligibility:v1"


class ArtifactReference(Frozen):
    identity: Hash
    digest: Hash


class SourceSnapshot(Frozen):
    incident_id: UUID
    experience: ArtifactReference
    evaluation: ArtifactReference
    feedback: tuple[ArtifactReference, ...]

    @model_validator(mode="after")
    def canonical(self) -> Self:
        ids = tuple(ref.identity for ref in self.feedback)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("Feedback references must be sorted and unique")
        return self


class ObjectiveContext(Frozen):
    """Selected existing facts; full outcome/metrics remain in the referenced Evaluation."""

    current_step: WorkflowStep
    next_step: WorkflowStep
    terminal: bool
    waiting_for_human: bool
    workflow_failure: WorkflowFailure | None
    governance_outcome: GovernanceOutcome
    execution_outcome: HistoricalOutcome
    orchestration_step_count: int = Field(ge=1)
    investigation_count: None = None
    tool_call_count: None = None
    analysis_observed: bool
    fusion_observed: bool


class SampleContent(Frozen):
    sample_schema_version: Literal["improvement-sample:v1"] = "improvement-sample:v1"
    sources: SourceSnapshot
    scope: Literal["overall"] = "overall"
    verdict: Verdict
    labels: tuple[DiagnosticLabel, ...]
    objective: ObjectiveContext

    @model_validator(mode="after")
    def eligible_shape(self) -> Self:
        if not self.sources.feedback or self.verdict == Verdict.INCONCLUSIVE:
            raise ValueError("Sample needs conclusive human labels")
        if tuple(sorted(set(self.labels))) != self.labels:
            raise ValueError("Labels must be sorted and unique")
        if self.labels and self.verdict != Verdict.INCORRECT:
            raise ValueError("Incorrect verdict required for defect labels")
        if {DiagnosticLabel.FALSE_POSITIVE, DiagnosticLabel.FALSE_NEGATIVE} <= set(self.labels):
            raise ValueError("Contradictory cross-feedback labels")
        if {DiagnosticLabel.UNNECESSARY_INVESTIGATION, DiagnosticLabel.MISSED_INVESTIGATION} <= set(
            self.labels
        ):
            raise ValueError("Contradictory investigation labels")
        return self


class ImprovementSample(Frozen):
    sample_id: Hash
    content: SampleContent

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if self.sample_id != content_digest(self.content):
            raise ValueError("Sample digest mismatch")
        return self


class EligibilityReason(StrEnum):
    ELIGIBLE = "eligible"
    NO_FEEDBACK = "excluded_no_feedback"
    INCONCLUSIVE = "excluded_inconclusive"
    ANALYST_DISAGREEMENT = "excluded_analyst_disagreement"
    UNSUPPORTED_SCOPE = "excluded_unsupported_scope"


class DatasetStatistics(Frozen):
    sample_count: int = Field(ge=0)
    correct_count: int = Field(ge=0)
    incorrect_count: int = Field(ge=0)
    false_positive_count: int = Field(ge=0)
    false_negative_count: int = Field(ge=0)
    exclusion_count: int = Field(ge=0)
    disagreement_count: int = Field(ge=0)


class EligibilityResult(Frozen):
    sources: SourceSnapshot
    reason: EligibilityReason
    sample: ArtifactReference | None = None

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if (self.reason == EligibilityReason.ELIGIBLE) != (self.sample is not None):
            raise ValueError("Eligibility/sample mismatch")
        if (self.reason == EligibilityReason.NO_FEEDBACK) != (not self.sources.feedback):
            raise ValueError("No-feedback exclusion mismatch")
        return self


class SourceSnapshotIdentity(Frozen):
    sources: tuple[SourceSnapshot, ...]


class DatasetManifest(Frozen):
    dataset_schema_version: Literal["improvement-dataset:v1"] = "improvement-dataset:v1"
    builder_version: Literal["soc-improvement-dataset-builder:v1"] = BUILDER_VERSION
    eligibility_version: Literal["soc-improvement-eligibility:v1"] = ELIGIBILITY_VERSION
    source_snapshot_id: Hash
    selection: tuple[EligibilityResult, ...]
    samples: tuple[ArtifactReference, ...]
    sample_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if self.source_snapshot_id != content_digest(
            SourceSnapshotIdentity(sources=tuple(item.sources for item in self.selection))
        ):
            raise ValueError("Source snapshot identity mismatch")
        evaluations = tuple(item.sources.evaluation.identity for item in self.selection)
        if evaluations != tuple(sorted(set(evaluations))):
            raise ValueError("Canonical evaluation selection required")
        samples = tuple(
            sorted((s.sample for s in self.selection if s.sample), key=lambda r: r.identity)
        )
        if self.samples != samples or len({r.identity for r in samples}) != len(samples):
            raise ValueError("Dataset sample membership mismatch")
        if self.sample_count != len(samples) or self.excluded_count != len(self.selection) - len(
            samples
        ):
            raise ValueError("Dataset counts mismatch")
        return self


class ImprovementDataset(Frozen):
    dataset_id: Hash
    # Content-addressed version, not a wall-clock or insertion-order sequence.
    dataset_version: Hash
    manifest_digest: Hash
    manifest: DatasetManifest
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if (
            not self.dataset_id
            == self.dataset_version
            == self.manifest_digest
            == content_digest(self.manifest)
        ):
            raise ValueError("Dataset manifest identity mismatch")
        return self


class DatasetExport(Frozen):
    export_version: Literal["improvement-dataset-export:v1"] = "improvement-dataset-export:v1"
    dataset_id: Hash
    dataset_version: Hash
    manifest_digest: Hash
    manifest: DatasetManifest
    samples: tuple[ImprovementSample, ...]
