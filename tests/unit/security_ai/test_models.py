from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import JsonValue, ValidationError

from soc_agent._json import canonical_json_object
from soc_agent.execution import ActionProposal
from soc_agent.security_ai import (
    SecurityAIInputType,
    SecurityAIModelMetadata,
    SecurityAIPrediction,
    SecurityAIRequest,
    SecurityAIResult,
    SecurityAITaskType,
)

from .conftest import FlowInput


@pytest.mark.parametrize(
    "update",
    [
        {"name": " "},
        {"name": "bad name"},
        {"name": "network_ids_mock\n"},
        {"version": " "},
        {"description": " "},
        {"task_type": "execute"},
        {"input_type": "arbitrary_shell"},
        {"extra": True},
    ],
)
def test_invalid_metadata(metadata: SecurityAIModelMetadata, update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SecurityAIModelMetadata.model_validate(metadata.model_dump() | update)


@pytest.mark.parametrize("task", list(SecurityAITaskType))
@pytest.mark.parametrize("input_type", list(SecurityAIInputType))
def test_metadata_roundtrip(
    metadata: SecurityAIModelMetadata, task: SecurityAITaskType, input_type: SecurityAIInputType
) -> None:
    data = SecurityAIModelMetadata.model_validate(
        metadata.model_dump()
        | {
            "task_type": task,
            "input_type": input_type,
        }
    )
    assert SecurityAIModelMetadata.model_validate_json(data.model_dump_json()) == data
    with pytest.raises(ValidationError):
        data.version = "2.0"


def test_request_and_result_snapshots(
    metadata: SecurityAIModelMetadata,
    prediction: dict[str, JsonValue],
    features: dict[str, JsonValue],
) -> None:
    request = SecurityAIRequest[FlowInput](
        incident_id=uuid4(), input=FlowInput.model_validate(features)
    )
    with pytest.raises(ValidationError):
        request.incident_id = uuid4()
    result = SecurityAIResult(
        incident_id=request.incident_id,
        model_name=metadata.name,
        model_version=metadata.version,
        task_type=metadata.task_type,
        **prediction,
    )
    assert result.result_id.version == 4
    assert result.created_at.utcoffset() == timedelta(0)
    assert SecurityAIResult.model_validate_json(result.model_dump_json()) == result
    assert result.model_name == metadata.name and result.model_version == metadata.version
    with pytest.raises(ValidationError):
        result.prediction = "benign"
    scores = result.scores_payload()
    scores["benign"] = 1.0
    explanation = result.explanation_payload()
    assert explanation is not None
    explanation["top_features"].append("changed")
    prediction["explanation"]["top_features"].clear()
    assert result.scores_payload()["benign"] == 0.06
    assert result.explanation_payload()["top_features"] == ["failed_connections", "unique_targets"]
    assert "input" not in result.model_dump()
    with pytest.raises(ValidationError):
        SecurityAIResult.model_validate(result.model_dump() | {"created_at": datetime(2026, 1, 1)})
    local = datetime(2026, 1, 1, 9, tzinfo=timezone(timedelta(hours=9)))
    changed = SecurityAIResult.model_validate(result.model_dump() | {"created_at": local})
    assert changed.created_at == datetime(2026, 1, 1, tzinfo=UTC)
    assert changed.created_at.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "update",
    [
        {"prediction": " "},
        {"confidence": -0.1},
        {"confidence": 1.1},
        {"confidence": float("nan")},
        {"confidence": float("inf")},
        {"scores": []},
        {"scores": {"x": object()}},
        {"scores": {1: 2}},
        {"scores": {"x": [float("nan")]}},
        {"explanation": {"x": float("inf")}},
        {"explanation": "not a JSON object"},
        {"extra": True},
    ],
)
def test_invalid_prediction(prediction: dict[str, JsonValue], update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SecurityAIPrediction.model_validate(prediction | update)


def test_scores_are_not_probabilities() -> None:
    prediction = SecurityAIPrediction(prediction="anomalous", scores={"margin": -3.7, "risk": 17})
    assert prediction.confidence is None
    assert prediction.explanation_payload() is None
    assert prediction.scores_payload() == {"margin": -3.7, "risk": 17}
    assert prediction.scores == canonical_json_object({"risk": 17, "margin": -3.7})
    assert prediction.scores == ActionProposal.canonical_input({"risk": 17, "margin": -3.7})


@pytest.mark.parametrize("confidence", [0.0, 1.0, None])
def test_confidence_boundaries(confidence: float | None) -> None:
    assert SecurityAIPrediction(prediction="benign", confidence=confidence).confidence == confidence


@pytest.mark.parametrize(
    "update",
    [
        {"confidence": -0.01},
        {"confidence": 1.01},
        {"scores": {"x": object()}},
        {"extra": True},
        {"model_version": " "},
        {"task_type": "unknown"},
    ],
)
def test_result_rejects_invalid_data(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SecurityAIResult.model_validate(
            {
                "incident_id": uuid4(),
                "model_name": "fixture",
                "model_version": "1",
                "task_type": "classification",
                "prediction": "benign",
            }
            | update
        )
