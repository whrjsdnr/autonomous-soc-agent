import asyncio
from uuid import uuid4

import pytest
from pydantic import BaseModel, Field, JsonValue, ValidationError

from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAI,
    SecurityAIInferenceError,
    SecurityAIInputValidationError,
    SecurityAIModelMetadata,
    SecurityAIOutputValidationError,
    SecurityAIPrediction,
    SecurityAIRequest,
    SecurityAIResult,
)

from .conftest import FlowInput


@pytest.mark.asyncio
async def test_valid_request(
    mock_ai: MockSecurityAI[FlowInput], features: dict[str, JsonValue]
) -> None:
    incident_id = uuid4()
    result = await mock_ai.model.predict({"incident_id": incident_id, "input": features})
    assert isinstance(result, SecurityAIResult)
    assert result.incident_id == incident_id
    assert result.model_name == "network_ids_mock" and result.model_version == "1.0.0"
    assert result.prediction == "credential_attack" and result.confidence == 0.94
    assert mock_ai.call_count == 1
    assert isinstance(mock_ai.requests[0].input, FlowInput)
    assert mock_ai.requests[0].input.tags == []


@pytest.mark.parametrize(
    "input",
    [
        {},
        {"duration": "attack", "failed_connections": 43, "unique_targets": 7},
        {"duration": 1, "failed_connections": -1, "unique_targets": 1},
    ],
)
@pytest.mark.asyncio
async def test_invalid_input_does_not_consume(
    mock_ai: MockSecurityAI[FlowInput], features: dict[str, JsonValue], input: dict[str, object]
) -> None:
    with pytest.raises(SecurityAIInputValidationError) as caught:
        await mock_ai.model.predict({"incident_id": uuid4(), "input": input})
    assert isinstance(caught.value.__cause__, ValidationError)
    assert mock_ai.call_count == 0
    assert (
        await mock_ai.model.predict({"incident_id": uuid4(), "input": features})
    ).prediction == "credential_attack"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["incident", "extra", "input_extra", "nested_model"])
async def test_envelope_and_models_revalidated(
    mock_ai: MockSecurityAI[FlowInput], features: dict[str, JsonValue], kind: str
) -> None:
    envelope: dict[str, object] = {"incident_id": uuid4(), "input": features}
    if kind == "incident":
        envelope["incident_id"] = "not uuid"
    elif kind == "extra":
        envelope["model_version"] = "99"
    elif kind == "input_extra":
        envelope["input"] = features | {"secret": "not accepted"}
    else:
        envelope["input"] = FlowInput.model_construct(
            duration="attack", failed_connections=43, unique_targets=7
        )
    with pytest.raises(SecurityAIInputValidationError):
        await mock_ai.model.predict(envelope)
    assert mock_ai.call_count == 0


@pytest.mark.asyncio
async def test_input_alias_defaults_and_handler_mutation(metadata: SecurityAIModelMetadata) -> None:
    class Input(BaseModel):
        values: list[int] = Field(alias="features")
        limit: int = 5

    async def handler(request: SecurityAIRequest[Input]) -> object:
        request.input.values.append(99)
        assert request.input.limit == 5
        return {"prediction": "benign"}

    model = SecurityAI(metadata, Input, handler)
    request = SecurityAIRequest[Input](incident_id=uuid4(), input=Input(features=[1]))
    result = await model.predict(request)
    assert request.input.values == [1]
    assert result.incident_id == request.incident_id
    assert "features" not in result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["result_id", "incident_id", "model_name", "model_version", "task_type", "created_at"]
)
async def test_handler_cannot_supply_provenance(
    metadata: SecurityAIModelMetadata, features: dict[str, JsonValue], field: str
) -> None:
    mock = MockSecurityAI(
        metadata=metadata,
        input_model=FlowInput,
        responses=[{"prediction": "malicious", field: "forged"}],
    )
    with pytest.raises(SecurityAIOutputValidationError):
        await mock.model.predict({"incident_id": uuid4(), "input": features})
    assert mock.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output",
    [
        None,
        [],
        {"prediction": " "},
        {"prediction": "x", "confidence": 2},
        {"prediction": "x", "scores": {"score": float("nan")}},
    ],
)
async def test_bad_output(
    metadata: SecurityAIModelMetadata, features: dict[str, JsonValue], output: JsonValue
) -> None:
    mock = MockSecurityAI(
        metadata=metadata, input_model=FlowInput, responses=[output, {"prediction": "next"}]
    )
    with pytest.raises(SecurityAIOutputValidationError):
        await mock.model.predict({"incident_id": uuid4(), "input": features})
    assert mock.call_count == 1  # No hidden retry consumed the next response.


@pytest.mark.asyncio
async def test_prebuilt_output_revalidated(
    metadata: SecurityAIModelMetadata, features: dict[str, JsonValue]
) -> None:
    async def handler(request: SecurityAIRequest[FlowInput]) -> object:
        return SecurityAIPrediction.model_construct(prediction="x", confidence=2)

    with pytest.raises(SecurityAIOutputValidationError):
        await SecurityAI(metadata, FlowInput, handler).predict(
            {"incident_id": uuid4(), "input": features}
        )


@pytest.mark.asyncio
async def test_inference_failure_no_retry(
    metadata: SecurityAIModelMetadata, features: dict[str, JsonValue]
) -> None:
    mock = MockSecurityAI(
        metadata=metadata,
        input_model=FlowInput,
        responses=[RuntimeError("MODEL_SECRET"), {"prediction": "next"}],
    )
    with pytest.raises(SecurityAIInferenceError) as caught:
        await mock.model.predict({"incident_id": uuid4(), "input": features})
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert "MODEL_SECRET" not in str(caught.value)
    assert mock.call_count == 1


@pytest.mark.asyncio
async def test_cancellation_propagates(
    metadata: SecurityAIModelMetadata, features: dict[str, JsonValue]
) -> None:
    async def handler(request: SecurityAIRequest[FlowInput]) -> object:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await SecurityAI(metadata, FlowInput, handler).predict(
            {"incident_id": uuid4(), "input": features}
        )


@pytest.mark.asyncio
async def test_complete_result_cannot_be_handler_output(
    metadata: SecurityAIModelMetadata,
    features: dict[str, JsonValue],
) -> None:
    async def handler(request: SecurityAIRequest[FlowInput]) -> object:
        return SecurityAIResult(
            incident_id=uuid4(),
            model_name="trusted_model",
            model_version="99",
            task_type=metadata.task_type,
            prediction="malicious",
        )

    with pytest.raises(SecurityAIOutputValidationError):
        await SecurityAI(metadata, FlowInput, handler).predict(
            {
                "incident_id": uuid4(),
                "input": features,
            }
        )


@pytest.mark.asyncio
async def test_valid_prediction_model_and_incident_isolation(
    metadata: SecurityAIModelMetadata,
    features: dict[str, JsonValue],
) -> None:
    async def handler(request: SecurityAIRequest[FlowInput]) -> object:
        return SecurityAIPrediction(prediction="benign")

    model = SecurityAI(metadata, FlowInput, handler)
    first_incident, second_incident = uuid4(), uuid4()
    first = await model.predict({"incident_id": first_incident, "input": features})
    second = await model.predict({"incident_id": second_incident, "input": features})
    assert first.incident_id == first_incident and second.incident_id == second_incident
    assert first.result_id != second.result_id
