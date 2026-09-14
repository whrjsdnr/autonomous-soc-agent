from datetime import datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import JsonValue, ValidationError

from soc_agent.assessment import (
    AssessmentResult,
    InvalidAnalysisReferenceError,
    InvalidEvidenceReferenceError,
    SecurityAnalysisDraft,
    ThreatAssessment,
)
from soc_agent.assessment.validator import convert_analysis
from soc_agent.state import Hypothesis, IncidentState, Observation, Severity


def test_conversion_ids_preservation_and_severity(
    state: IncidentState, response: dict[str, JsonValue]
) -> None:
    old_observation = Observation(
        statement="Existing direct fact", supporting_evidence_ids=(state.evidence[0].evidence_id,)
    )
    old_hypothesis = Hypothesis(
        statement="Existing possible explanation",
        supporting_evidence_ids=(state.evidence[0].evidence_id,),
        confidence=0.2,
    )
    state = state.add_observation(old_observation).add_hypothesis(old_hypothesis)
    result = convert_analysis(SecurityAnalysisDraft.model_validate(response), state)
    updated, assessment = result.incident_state, result.threat_assessment
    assert updated.observations[0] == old_observation
    assert updated.hypotheses[0] == old_hypothesis
    assert len(updated.observations) == len(updated.hypotheses) == 2
    assert assessment.supporting_observation_ids == (updated.observations[1].observation_id,)
    assert assessment.supporting_hypothesis_ids == (updated.hypotheses[1].hypothesis_id,)
    assert isinstance(assessment.supporting_observation_ids[0], UUID)
    assert assessment.assessment_id.version == 4
    assert assessment.created_at.utcoffset() == timedelta(0)
    assert assessment.severity is Severity.HIGH
    assert updated.severity == state.severity
    assert updated.confidence == state.confidence
    assert updated.status == state.status
    assert updated.evidence == state.evidence
    assert len(state.observations) == len(state.hypotheses) == 1
    assert AssessmentResult.model_validate_json(result.model_dump_json()) == result
    with pytest.raises(ValidationError):
        assessment.summary = "changed"
    with pytest.raises(ValidationError):
        ThreatAssessment.model_validate(
            assessment.model_dump() | {"created_at": datetime(2026, 1, 1)}
        )


@pytest.mark.parametrize("section", ["observations", "hypotheses", "assessment"])
def test_unknown_evidence(
    state: IncidentState, response: dict[str, JsonValue], section: str
) -> None:
    if section == "assessment":
        response[section]["supporting_evidence_ids"] = [str(uuid4())]
    else:
        response[section][0]["supporting_evidence_ids"] = [str(uuid4())]
    with pytest.raises(InvalidEvidenceReferenceError):
        convert_analysis(SecurityAnalysisDraft.model_validate(response), state)
    assert state.observations == state.hypotheses == ()


def test_cross_incident_and_atomic_conversion(
    state: IncidentState, response: dict[str, JsonValue]
) -> None:
    from soc_agent.state import Evidence

    foreign = Evidence.model_validate(
        state.evidence[0].model_dump() | {"incident_id": uuid4(), "evidence_id": uuid4()}
    )
    response["observations"].append(
        {
            "ref": "O2",
            "statement": "Invalid second observation",
            "supporting_evidence_ids": [str(foreign.evidence_id)],
        }
    )
    before = state.model_dump_json()
    with pytest.raises(InvalidEvidenceReferenceError):
        convert_analysis(SecurityAnalysisDraft.model_validate(response), state)
    assert state.model_dump_json() == before


@pytest.mark.parametrize(
    "field,ref", [("supporting_observation_refs", "O999"), ("supporting_hypothesis_refs", "H999")]
)
def test_unknown_local_refs(
    state: IncidentState, response: dict[str, JsonValue], field: str, ref: str
) -> None:
    response["assessment"][field] = [ref]
    with pytest.raises(InvalidAnalysisReferenceError):
        convert_analysis(SecurityAnalysisDraft.model_validate(response), state)
    assert state.observations == state.hypotheses == ()


def test_result_rejects_wrong_incident(
    state: IncidentState, response: dict[str, JsonValue]
) -> None:
    result = convert_analysis(SecurityAnalysisDraft.model_validate(response), state)
    with pytest.raises(ValidationError):
        AssessmentResult.model_validate(
            result.model_dump()
            | {
                "threat_assessment": result.threat_assessment.model_dump()
                | {"incident_id": uuid4()}
            }
        )
