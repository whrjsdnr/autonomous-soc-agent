from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.state import (
    Evidence,
    Hypothesis,
    IncidentState,
    IncidentStatus,
    Observation,
    Severity,
)


def make_evidence(state: IncidentState) -> Evidence:
    return Evidence(
        incident_id=state.incident_id,
        source="auth.log",
        summary="327 failed login attempts",
        raw_data="failed_login_count=327",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_defaults_and_independent_collections() -> None:
    first, second = IncidentState(), IncidentState()
    assert first.incident_id != second.incident_id
    assert first.status is IncidentStatus.NEW
    assert first.severity is Severity.INFO
    assert first.confidence is None
    assert first.created_at.utcoffset() == timedelta(0)
    assert first.updated_at >= first.created_at
    updated = first.add_evidence(make_evidence(first))
    assert len(updated.evidence) == 1
    assert first.evidence == second.evidence == ()
    assert first.observations == second.observations == ()
    assert first.hypotheses == second.hypotheses == ()


def test_add_records_and_json_roundtrip() -> None:
    original = IncidentState()
    evidence = make_evidence(original)
    observation = Observation(
        statement="327 failures", supporting_evidence_ids=(evidence.evidence_id,)
    )
    hypothesis = Hypothesis(
        statement="Possible brute force",
        supporting_evidence_ids=(evidence.evidence_id,),
        confidence=0.7,
    )
    state = original.add_evidence(evidence).add_observation(observation).add_hypothesis(hypothesis)
    assert state.evidence == (evidence,)
    assert state.observations == (observation,)
    assert state.hypotheses == (hypothesis,)
    assert original.observations == original.hypotheses == ()
    assert state.created_at == original.created_at
    assert state.updated_at >= original.updated_at
    assert IncidentState.model_validate_json(state.model_dump_json()) == state
    for method, record in (
        (state.add_evidence, evidence),
        (state.add_observation, observation),
        (state.add_hypothesis, hypothesis),
    ):
        with pytest.raises(ValidationError, match="Duplicate"):
            method(record)
    assert len(state.evidence) == len(state.observations) == len(state.hypotheses) == 1


@pytest.mark.parametrize("field", ["observations", "hypotheses"])
def test_missing_references_rejected_on_creation_and_addition(field: str) -> None:
    state = IncidentState()
    data = {"statement": "A statement", "supporting_evidence_ids": (uuid4(),)}
    record = (
        Observation.model_validate(data)
        if field == "observations"
        else Hypothesis.model_validate(data | {"confidence": 0.5})
    )
    with pytest.raises(ValidationError, match="Supporting evidence"):
        IncidentState.model_validate({field: [record]})
    with pytest.raises(ValidationError, match="Supporting evidence"):
        if isinstance(record, Observation):
            state.add_observation(record)
        else:
            state.add_hypothesis(record)
    assert state.observations == state.hypotheses == ()


def test_cross_incident_evidence_rejected() -> None:
    state = IncidentState()
    evidence = make_evidence(IncidentState())
    with pytest.raises(ValidationError, match="belong"):
        state.add_evidence(evidence)
    with pytest.raises(ValidationError, match="belong"):
        IncidentState(evidence=(evidence,))


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "responding"),
        ("severity", "urgent"),
        ("confidence", -0.1),
        ("confidence", 1.1),
        ("confidence", float("nan")),
        ("created_at", datetime(2026, 1, 1)),
        ("updated_at", datetime(2026, 1, 1)),
    ],
)
def test_invalid_state_values(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        IncidentState.model_validate({field: value})


@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("status", list(IncidentStatus))
def test_enum_serialization(severity: Severity, status: IncidentStatus) -> None:
    state = IncidentState(severity=severity.value, status=status.value)
    assert state.severity is severity
    assert state.status is status
    assert state.model_dump(mode="json")["severity"] == severity.value


def test_immutable_state_and_distinct_record_types() -> None:
    state = IncidentState()
    with pytest.raises(ValidationError):
        state.incident_id = uuid4()
    hypothesis = Hypothesis(
        statement="Possible attack", supporting_evidence_ids=(uuid4(),), confidence=1
    )
    with pytest.raises(ValidationError):
        state.add_evidence(hypothesis)
    with pytest.raises(ValidationError):
        IncidentState.model_validate({"unexpected": "field"})


def test_timestamp_order() -> None:
    with pytest.raises(ValidationError, match="updated_at"):
        IncidentState(
            created_at=datetime(2026, 1, 2, tzinfo=UTC),
            updated_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
