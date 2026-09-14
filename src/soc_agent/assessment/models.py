"""Separate source-grounded descriptions, interpretations, and advisory risk judgments."""

from typing import Annotated, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from soc_agent.state import IncidentState, Severity
from soc_agent.state.evidence import Confidence, UTCTimestamp, utc_now

Statement = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
Summary = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]
ObservationRef = Annotated[str, StringConstraints(pattern=r"^O[1-9][0-9]*$", max_length=16)]
HypothesisRef = Annotated[str, StringConstraints(pattern=r"^H[1-9][0-9]*$", max_length=16)]
EvidenceReferences = Annotated[tuple[UUID, ...], Field(min_length=1, max_length=128)]


class ObservationDraft(BaseModel):
    """Direct description of evidence; no attacker intent inferred as fact."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    ref: ObservationRef
    statement: Statement
    supporting_evidence_ids: EvidenceReferences


class HypothesisDraft(BaseModel):
    """An explicitly uncertain interpretation, never an evidence record."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    ref: HypothesisRef
    statement: Statement
    supporting_evidence_ids: EvidenceReferences
    confidence: Confidence


class ThreatAssessmentDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    severity: Severity
    confidence: Confidence
    summary: Summary
    supporting_evidence_ids: EvidenceReferences
    supporting_observation_refs: tuple[ObservationRef, ...] = Field(default=(), max_length=12)
    supporting_hypothesis_refs: tuple[HypothesisRef, ...] = Field(default=(), max_length=8)


class SecurityAnalysisDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    observations: tuple[ObservationDraft, ...] = Field(max_length=12)
    hypotheses: tuple[HypothesisDraft, ...] = Field(max_length=8)
    assessment: ThreatAssessmentDraft

    @model_validator(mode="after")
    def unique_local_refs(self) -> Self:
        for refs in (
            [item.ref for item in self.observations],
            [item.ref for item in self.hypotheses],
        ):
            if len(refs) != len(set(refs)):
                raise ValueError("Duplicate draft-local refs are not allowed")
        return self


class ThreatAssessment(BaseModel):
    """Advisory current-risk judgment, not an action or lifecycle authorization."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    assessment_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    severity: Severity
    confidence: Confidence
    summary: Summary
    supporting_evidence_ids: EvidenceReferences
    supporting_observation_ids: tuple[UUID, ...] = ()
    supporting_hypothesis_ids: tuple[UUID, ...] = ()
    created_at: UTCTimestamp = Field(default_factory=utc_now)


class AssessmentResult(BaseModel):
    """Validated incident snapshot plus a separately returned assessment."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    incident_state: IncidentState
    threat_assessment: ThreatAssessment

    @model_validator(mode="after")
    def validate_links(self) -> Self:
        state, assessment = self.incident_state, self.threat_assessment
        if state.incident_id != assessment.incident_id:
            raise ValueError("Assessment and state incident IDs differ")
        for references, known in (
            (assessment.supporting_evidence_ids, {e.evidence_id for e in state.evidence}),
            (assessment.supporting_observation_ids, {o.observation_id for o in state.observations}),
            (assessment.supporting_hypothesis_ids, {h.hypothesis_id for h in state.hypotheses}),
        ):
            if not set(references) <= known:
                raise ValueError("Assessment reference is absent from incident state")
        return self
