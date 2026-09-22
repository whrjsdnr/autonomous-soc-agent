"""Optional model-derived context, kept separate from evidence and state updates."""

from typing import Self

from pydantic import Field, JsonValue, model_validator

from soc_agent.assessment.errors import AssessmentError, InvalidEvidenceReferenceError
from soc_agent.assessment.models import (
    AssessmentResult,
    HypothesisDraft,
    ObservationDraft,
    SecurityAnalysisDraft,
)
from soc_agent.security_ai.fusion.models import FusionResult
from soc_agent.security_ai.fusion.result_validation import validate_fusion_result
from soc_agent.state import IncidentState


class InvalidFusionContextError(AssessmentError):
    """Fusion is invalid or belongs to another incident; no LLM call is made."""


class FusionAnalysisDraft(SecurityAnalysisDraft):
    """Fusion-aware mode returns advisory analysis without proposing new state facts."""

    observations: tuple[ObservationDraft, ...] = Field(default=(), max_length=0)
    hypotheses: tuple[HypothesisDraft, ...] = Field(default=(), max_length=0)


class FusionAssessmentResult(AssessmentResult):
    """An unchanged state and advisory assessment with a separate analytical lineage."""

    model_derived_context: FusionResult

    @model_validator(mode="after")
    def validate_model_context(self) -> Self:
        validate_assessment_fusion(self.model_derived_context, self.incident_state)
        return self


def validate_assessment_fusion(value: FusionResult, state: IncidentState) -> FusionResult:
    from soc_agent.security_ai.fusion.errors import FusionValidationError

    try:
        result = validate_fusion_result(value)
    except FusionValidationError as error:
        raise InvalidFusionContextError(str(error)) from error
    if result.incident_id != state.incident_id:
        raise InvalidFusionContextError("Fusion and assessment incident IDs differ")
    references = {eid for signal in result.signals for eid in signal.source_evidence_ids}
    references.update(
        source.source_evidence_id
        for contribution in result.contributions
        for source in contribution.provenance.sources
        if source.source_evidence_id is not None
    )
    if not references <= {e.evidence_id for e in state.evidence}:
        raise InvalidEvidenceReferenceError("Fusion references evidence absent from this incident")
    return result


def fusion_prompt_context(result: FusionResult) -> dict[str, JsonValue]:
    """Project inference metadata; omit numerical preprocessing arrays, never analytical fields."""
    context = result.model_dump(mode="json", exclude={"model_references", "signals"})
    context["model_references"] = [
        {"manifest_digest": b.manifest_digest, "manifest": b.manifest.model_dump(mode="json")}
        for b in result.model_references
    ]
    context["signal_lineage"] = [
        s.model_dump(mode="json", exclude={"explanation", "scores"}) for s in result.signals
    ]
    return context
