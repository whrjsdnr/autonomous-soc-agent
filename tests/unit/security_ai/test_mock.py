from uuid import uuid4

import pytest
from pydantic import JsonValue

from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAIInferenceError,
    SecurityAIMockExhaustedError,
    SecurityAIModelMetadata,
)

from .conftest import FlowInput


@pytest.mark.asyncio
async def test_sequence_history_exhaustion(
    metadata: SecurityAIModelMetadata, features: dict[str, JsonValue]
) -> None:
    mock = MockSecurityAI(
        metadata=metadata,
        input_model=FlowInput,
        responses=[
            {"prediction": "first"},
            SecurityAIInferenceError("Fixture failure"),
            {"prediction": "third"},
        ],
    )
    incident_id = uuid4()
    request = {"incident_id": incident_id, "input": features}
    first = await mock.model.predict(request)
    history = mock.requests
    with pytest.raises(SecurityAIInferenceError, match="Fixture failure"):
        await mock.model.predict(request)
    third = await mock.model.predict(request)
    assert (first.prediction, third.prediction) == ("first", "third")
    assert first.result_id != third.result_id
    assert first.incident_id == third.incident_id == incident_id
    assert len(history) == 1 and mock.call_count == 3
    mock.requests[0].input.tags.append("changed")
    assert mock.requests[0].input.tags == []
    with pytest.raises(SecurityAIMockExhaustedError):
        await mock.model.predict(request)
    assert mock.call_count == 4


@pytest.mark.asyncio
async def test_fixture_and_model_isolation(
    metadata: SecurityAIModelMetadata, features: dict[str, JsonValue]
) -> None:
    scores: dict[str, JsonValue] = {"anomaly_score": 0.87}
    responses: list[JsonValue] = [{"prediction": "anomalous", "scores": scores}]
    first = MockSecurityAI(metadata=metadata, input_model=FlowInput, responses=[])
    second = MockSecurityAI(metadata=metadata, input_model=FlowInput, responses=responses)
    scores.clear()
    responses.clear()
    request = {"incident_id": uuid4(), "input": features}
    with pytest.raises(SecurityAIMockExhaustedError):
        await first.model.predict(request)
    assert second.call_count == 0
    result = await second.model.predict(request)
    assert result.scores_payload() == {"anomaly_score": 0.87}
    assert second.call_count == 1
