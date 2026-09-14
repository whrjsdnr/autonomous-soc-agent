from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from soc_agent.state import Evidence, Hypothesis, Observation


def evidence_data() -> dict[str, object]:
    return {
        "incident_id": uuid4(),
        "source": "auth.log",
        "summary": "327 failed login attempts",
        "raw_data": "  failed_login_count=327\n",
        "observed_at": datetime(2026, 1, 1, tzinfo=UTC),
    }


def test_evidence_provenance_and_serialization() -> None:
    evidence = Evidence.model_validate(evidence_data())
    assert isinstance(evidence.evidence_id, UUID)
    assert evidence.evidence_id.version == 4
    assert evidence.raw_data == "  failed_login_count=327\n"
    assert evidence.collected_at.utcoffset() == timedelta(0)
    assert evidence.reliability is None
    assert Evidence.model_validate_json(evidence.model_dump_json()) == evidence


@pytest.mark.parametrize("field", ["source", "summary", "tool_name"])
@pytest.mark.parametrize("value", ["", "   "])
def test_required_text_is_not_blank(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Evidence.model_validate(evidence_data() | {field: value})


@pytest.mark.parametrize("field", ["incident_id", "source", "summary", "raw_data", "observed_at"])
def test_required_fields(field: str) -> None:
    data = evidence_data()
    del data[field]
    with pytest.raises(ValidationError):
        Evidence.model_validate(data)


@pytest.mark.parametrize("field", ["observed_at", "collected_at"])
def test_evidence_rejects_naive_time(field: str) -> None:
    with pytest.raises(ValidationError):
        Evidence.model_validate(evidence_data() | {field: datetime(2026, 1, 1)})


def test_offset_time_is_normalized_to_utc() -> None:
    observed = datetime(2026, 1, 1, 9, tzinfo=timezone(timedelta(hours=9)))
    evidence = Evidence.model_validate(evidence_data() | {"observed_at": observed})
    assert evidence.observed_at == datetime(2026, 1, 1, tzinfo=UTC)
    assert evidence.observed_at.utcoffset() == timedelta(0)


@pytest.mark.parametrize("raw_data", ["", {}, ["record"]])
def test_raw_data_requires_nonempty_text(raw_data: object) -> None:
    with pytest.raises(ValidationError):
        Evidence.model_validate(evidence_data() | {"raw_data": raw_data})


def test_records_are_independent_and_immutable() -> None:
    first = Evidence.model_validate(evidence_data())
    second = Evidence.model_validate(evidence_data())
    assert first.evidence_id != second.evidence_id
    with pytest.raises(ValidationError):
        first.summary = "changed"
    assert second.summary == "327 failed login attempts"
    references = [first.evidence_id]
    observation = Observation(statement="327 failures", supporting_evidence_ids=references)
    references.clear()
    assert observation.supporting_evidence_ids == (first.evidence_id,)


@pytest.mark.parametrize("model", [Observation, Hypothesis])
def test_statement_references_and_time(model: type[Observation] | type[Hypothesis]) -> None:
    data = {"statement": "A statement", "supporting_evidence_ids": [uuid4()]}
    if model is Hypothesis:
        data["confidence"] = 0.5
    record = model.model_validate(data)
    assert record.created_at.utcoffset() == timedelta(0)
    for update in (
        {"statement": "  "},
        {"supporting_evidence_ids": []},
        {"created_at": datetime(2026, 1, 1)},
    ):
        with pytest.raises(ValidationError):
            model.model_validate(data | update)


@pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
def test_hypothesis_confidence_boundaries(confidence: float) -> None:
    hypothesis = Hypothesis(
        statement="Source may be brute forcing",
        supporting_evidence_ids=(uuid4(),),
        confidence=confidence,
    )
    assert hypothesis.confidence == confidence
    assert not isinstance(hypothesis, Evidence)


@pytest.mark.parametrize("confidence", [-0.01, 1.01, float("nan"), float("inf")])
def test_invalid_confidence_and_reliability(confidence: float) -> None:
    with pytest.raises(ValidationError):
        Hypothesis(
            statement="Possible attack", supporting_evidence_ids=(uuid4(),), confidence=confidence
        )
    with pytest.raises(ValidationError):
        Evidence.model_validate(evidence_data() | {"reliability": confidence})
