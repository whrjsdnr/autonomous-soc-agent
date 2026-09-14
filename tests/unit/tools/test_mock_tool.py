import asyncio

import pytest
from pydantic import BaseModel, JsonValue, ValidationError

from soc_agent.tools import (
    MockTool,
    Tool,
    ToolError,
    ToolExecutionError,
    ToolInputValidationError,
    ToolMockExhaustedError,
    ToolOutputValidationError,
)


@pytest.mark.asyncio
async def test_sequence_history_and_exhaustion(mock_tool: MockTool) -> None:
    first = await mock_tool.tool.execute({"query": "one"})
    second = await mock_tool.tool.execute({"query": "two"})
    assert first.output.matches == ["first"]
    assert second.output.matches == ["second"]
    assert [item.query for item in mock_tool.received_inputs] == ["one", "two"]
    mock_tool.received_inputs[0].query = "changed"
    assert mock_tool.received_inputs[0].query == "one"
    with pytest.raises(ToolMockExhaustedError):
        await mock_tool.tool.execute({"query": "three"})
    assert mock_tool.call_count == 3


@pytest.mark.parametrize("payload", [{}, {"query": 1}, {"query": "ok", "extra": True}])
@pytest.mark.asyncio
async def test_invalid_input_never_executes(
    mock_tool: MockTool, payload: dict[str, object]
) -> None:
    with pytest.raises(ToolInputValidationError) as caught:
        await mock_tool.tool.execute(payload)
    assert isinstance(caught.value.__cause__, ValidationError)
    assert mock_tool.call_count == 0
    assert mock_tool.received_inputs == ()
    result = await mock_tool.tool.execute({"query": "ok"})
    assert result.output.matches == ["first"]


@pytest.mark.parametrize("payload", [{}, {"matches": 1}, {"matches": [], "extra": True}, None])
@pytest.mark.asyncio
async def test_invalid_output_is_distinct(mock_tool: MockTool, payload: JsonValue) -> None:
    tool = mock_tool.tool
    mock = MockTool(
        metadata=tool.metadata,
        input_model=tool.input_model,
        output_model=tool.output_model,
        responses=[payload, {"matches": []}],
    )
    with pytest.raises(ToolOutputValidationError) as caught:
        await mock.tool.execute({"query": "ok"})
    assert isinstance(caught.value.__cause__, ValidationError)
    assert mock.call_count == 1
    assert (await mock.tool.execute({"query": "ok"})).output.matches == []


@pytest.mark.asyncio
async def test_configured_failure_is_execution_error(mock_tool: MockTool) -> None:
    tool = mock_tool.tool
    mock = MockTool(
        metadata=tool.metadata,
        input_model=tool.input_model,
        output_model=tool.output_model,
        responses=[RuntimeError("adapter failure")],
    )
    with pytest.raises(ToolExecutionError) as caught:
        await mock.tool.execute({"query": "ok"})
    assert isinstance(caught.value, ToolError)
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert mock.call_count == 1


@pytest.mark.asyncio
async def test_model_instances_are_revalidated(mock_tool: MockTool) -> None:
    tool = mock_tool.tool
    invalid_input = tool.input_model.model_construct(query=123)
    with pytest.raises(ToolInputValidationError):
        await tool.execute(invalid_input)
    assert mock_tool.call_count == 0

    async def bad_output(input_data: BaseModel) -> object:
        return tool.output_model.model_construct()

    wrapped = Tool(tool.metadata, tool.input_model, tool.output_model, bad_output)
    with pytest.raises(ToolOutputValidationError):
        await wrapped.execute({"query": "ok"})


@pytest.mark.asyncio
async def test_cancellation_propagates(mock_tool: MockTool) -> None:
    async def cancelled(input_data: BaseModel) -> object:
        raise asyncio.CancelledError

    tool = mock_tool.tool
    wrapped = Tool(tool.metadata, tool.input_model, tool.output_model, cancelled)
    with pytest.raises(asyncio.CancelledError):
        await wrapped.execute({"query": "ok"})


@pytest.mark.asyncio
async def test_fixture_copy_and_independent_instances(mock_tool: MockTool) -> None:
    matches = ["original"]
    responses: list[JsonValue] = [{"matches": matches}]
    tool = mock_tool.tool
    mock = MockTool(
        metadata=tool.metadata,
        input_model=tool.input_model,
        output_model=tool.output_model,
        responses=responses,
    )
    matches.clear()
    responses.clear()
    assert (await mock.tool.execute({"query": "ok"})).output.matches == ["original"]
    assert mock_tool.call_count == 0
