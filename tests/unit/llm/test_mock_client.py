import pytest
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from soc_agent.llm import (
    LLMClient,
    LLMError,
    LLMMockExhaustedError,
    LLMRequest,
    LLMResponseValidationError,
    LLMTimeoutError,
    MockLLMClient,
)


class SampleResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    label: str
    confidence: float = Field(ge=0, le=1)


class OtherResult(BaseModel):
    count: int


@pytest.fixture
def llm_request() -> LLMRequest:
    return LLMRequest(system_prompt="Instructions", user_prompt="Input")


@pytest.mark.asyncio
async def test_protocol_typed_client_returns_validated_result(llm_request: LLMRequest) -> None:
    client: LLMClient = MockLLMClient(responses=[{"label": "first", "confidence": 0.5}])
    result = await client.generate_structured(request=llm_request, response_model=SampleResult)
    assert isinstance(result, SampleResult)
    assert result.label == "first"
    assert result.confidence == 0.5


@pytest.mark.asyncio
async def test_order_history_and_multiple_schemas(llm_request: LLMRequest) -> None:
    client = MockLLMClient(responses=[{"label": "first", "confidence": 1.0}, {"count": 2}])
    second_request = LLMRequest(system_prompt="Instructions", user_prompt="Second input")
    assert client.call_count == 0
    first = await client.generate_structured(request=llm_request, response_model=SampleResult)
    history = client.requests
    second = await client.generate_structured(request=second_request, response_model=OtherResult)
    assert first.label == "first"
    assert second.count == 2
    assert client.requests == (llm_request, second_request)
    assert client.call_count == 2
    assert history == (llm_request,)
    with pytest.raises(LLMMockExhaustedError):
        await client.generate_structured(request=llm_request, response_model=SampleResult)
    assert client.call_count == 3


@pytest.mark.parametrize(
    "payload",
    [
        {"label": 123, "confidence": 0.5},
        {"label": "missing confidence"},
        {"label": "bad confidence", "confidence": 2},
        {"label": "extra", "confidence": 0.5, "unknown": True},
        {"label": "wrong type", "confidence": "0.5"},
        None,
        [],
        "not an object",
    ],
)
@pytest.mark.asyncio
async def test_invalid_response_is_boundary_error(
    payload: JsonValue, llm_request: LLMRequest
) -> None:
    client = MockLLMClient(responses=[payload, {"label": "next", "confidence": 0}])
    with pytest.raises(LLMResponseValidationError) as caught:
        await client.generate_structured(request=llm_request, response_model=SampleResult)
    assert isinstance(caught.value.__cause__, ValidationError)
    assert client.requests == (llm_request,)
    result = await client.generate_structured(request=llm_request, response_model=SampleResult)
    assert result.label == "next"
    assert client.call_count == 2


@pytest.mark.asyncio
async def test_empty_client_and_independent_histories(llm_request: LLMRequest) -> None:
    first, second = MockLLMClient([]), MockLLMClient([])
    with pytest.raises(LLMMockExhaustedError, match="No configured"):
        await first.generate_structured(request=llm_request, response_model=SampleResult)
    assert first.call_count == 1
    assert second.call_count == 0
    assert second.requests == ()


@pytest.mark.asyncio
async def test_fixture_mutation_does_not_change_response(llm_request: LLMRequest) -> None:
    class NestedResult(BaseModel):
        labels: list[str]

    labels = ["original"]
    responses: list[JsonValue] = [{"labels": labels}]
    client = MockLLMClient(responses)
    labels.append("modified")
    responses.clear()
    result = await client.generate_structured(request=llm_request, response_model=NestedResult)
    assert result.labels == ["original"]


@pytest.mark.parametrize(
    "error_type", [LLMTimeoutError, LLMResponseValidationError, LLMMockExhaustedError]
)
def test_errors_share_root(error_type: type[LLMError]) -> None:
    assert isinstance(error_type("failure"), LLMError)
