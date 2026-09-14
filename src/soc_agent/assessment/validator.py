"""Validate every reference before constructing any updated state snapshot."""

from pydantic import ValidationError

from soc_agent.assessment.errors import (
    InvalidAnalysisReferenceError,
    InvalidAssessmentDraftError,
    InvalidEvidenceReferenceError,
    NoEvidenceError,
)
from soc_agent.assessment.models import AssessmentResult, SecurityAnalysisDraft, ThreatAssessment
from soc_agent.state import Hypothesis, IncidentState, Observation


def convert_analysis(draft: SecurityAnalysisDraft, state: IncidentState) -> AssessmentResult:
    """Reference integrity is deterministic; semantic entailment is not proven here."""
    state = IncidentState.model_validate(state.model_dump(warnings=False))
    if not state.evidence:
        raise NoEvidenceError("Cannot assess an incident without evidence")
    try:
        draft = SecurityAnalysisDraft.model_validate(draft.model_dump(warnings=False))
    except ValidationError as error:
        raise InvalidAssessmentDraftError("Invalid structured analysis draft") from error
    evidence_ids = {e.evidence_id for e in state.evidence}
    for item in (*draft.observations, *draft.hypotheses, draft.assessment):
        if not set(item.supporting_evidence_ids) <= evidence_ids:
            raise InvalidEvidenceReferenceError(
                "Analysis references evidence outside this incident"
            )
    observation_refs = {item.ref for item in draft.observations}
    hypothesis_refs = {item.ref for item in draft.hypotheses}
    if not set(draft.assessment.supporting_observation_refs) <= observation_refs:
        raise InvalidAnalysisReferenceError("Unknown observation draft ref")
    if not set(draft.assessment.supporting_hypothesis_refs) <= hypothesis_refs:
        raise InvalidAnalysisReferenceError("Unknown hypothesis draft ref")

    observations = {
        item.ref: Observation(
            statement=item.statement, supporting_evidence_ids=item.supporting_evidence_ids
        )
        for item in draft.observations
    }
    hypotheses = {
        item.ref: Hypothesis(
            statement=item.statement,
            supporting_evidence_ids=item.supporting_evidence_ids,
            confidence=item.confidence,
        )
        for item in draft.hypotheses
    }
    updated = state
    for observation in observations.values():
        updated = updated.add_observation(observation)
    for hypothesis in hypotheses.values():
        updated = updated.add_hypothesis(hypothesis)
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity=draft.assessment.severity,
        confidence=draft.assessment.confidence,
        summary=draft.assessment.summary,
        supporting_evidence_ids=draft.assessment.supporting_evidence_ids,
        supporting_observation_ids=tuple(
            observations[ref].observation_id for ref in draft.assessment.supporting_observation_refs
        ),
        supporting_hypothesis_ids=tuple(
            hypotheses[ref].hypothesis_id for ref in draft.assessment.supporting_hypothesis_refs
        ),
    )
    return AssessmentResult(incident_state=updated, threat_assessment=assessment)
