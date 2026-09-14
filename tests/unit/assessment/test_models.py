import pytest
from pydantic import JsonValue, ValidationError

from soc_agent.assessment import (
    HypothesisDraft,
    ObservationDraft,
    SecurityAnalysisDraft,
    ThreatAssessmentDraft,
)


def test_valid_models(response: dict[str, JsonValue]) -> None:
    draft = SecurityAnalysisDraft.model_validate(response)
    assert isinstance(draft.observations[0], ObservationDraft)
    assert isinstance(draft.hypotheses[0], HypothesisDraft)
    assert isinstance(draft.assessment, ThreatAssessmentDraft)
    assert SecurityAnalysisDraft.model_validate_json(draft.model_dump_json()) == draft


@pytest.mark.parametrize(
    "field,value",
    [
        ("statement", " "),
        ("supporting_evidence_ids", []),
        ("ref", " "),
        ("ref", "H1"),
        ("observation_id", "forged"),
        ("created_at", "forged"),
    ],
)
def test_invalid_observation(response: dict[str, JsonValue], field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        ObservationDraft.model_validate(response["observations"][0] | {field: value})


@pytest.mark.parametrize("confidence", [-0.1, 1.1, float("nan"), float("inf")])
def test_invalid_confidence(response: dict[str, JsonValue], confidence: float) -> None:
    with pytest.raises(ValidationError):
        HypothesisDraft.model_validate(response["hypotheses"][0] | {"confidence": confidence})
    with pytest.raises(ValidationError):
        ThreatAssessmentDraft.model_validate(response["assessment"] | {"confidence": confidence})


@pytest.mark.parametrize("confidence", [0.0, 1.0])
def test_confidence_boundaries(response: dict[str, JsonValue], confidence: float) -> None:
    assert (
        HypothesisDraft.model_validate(
            response["hypotheses"][0] | {"confidence": confidence}
        ).confidence
        == confidence
    )


@pytest.mark.parametrize("field", ["observations", "hypotheses"])
def test_duplicate_refs(response: dict[str, JsonValue], field: str) -> None:
    with pytest.raises(ValidationError, match="Duplicate"):
        SecurityAnalysisDraft.model_validate(response | {field: response[field] * 2})


@pytest.mark.parametrize("field,count,prefix", [("observations", 13, "O"), ("hypotheses", 9, "H")])
def test_count_limits(response: dict[str, JsonValue], field: str, count: int, prefix: str) -> None:
    values = [response[field][0] | {"ref": f"{prefix}{i + 1}"} for i in range(count)]
    with pytest.raises(ValidationError):
        SecurityAnalysisDraft.model_validate(response | {field: values})


@pytest.mark.parametrize(
    "update",
    [
        {"summary": "x" * 4001},
        {"severity": "urgent"},
        {"supporting_evidence_ids": []},
        {"approval_id": "forged"},
    ],
)
def test_invalid_assessment(response: dict[str, JsonValue], update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ThreatAssessmentDraft.model_validate(response["assessment"] | update)
