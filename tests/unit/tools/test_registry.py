import pytest

from soc_agent.tools import MockTool, Tool, ToolNotFoundError, ToolRegistrationError, ToolRegistry


def test_registration_listing_and_duplicates(mock_tool: MockTool) -> None:
    registry = ToolRegistry()
    assert registry.list() == ()
    registry.register(mock_tool.tool)
    assert "log_search" in registry
    assert registry.get("log_search") is mock_tool.tool
    snapshot = registry.list()
    second = Tool(
        mock_tool.tool.metadata.model_copy(update={"name": "other_search"}),
        mock_tool.tool.input_model,
        mock_tool.tool.output_model,
        mock_tool.tool.handler,
    )
    registry.register(second)
    assert len(registry.list()) == 2
    assert len(snapshot) == 1
    with pytest.raises(ToolRegistrationError):
        registry.register(mock_tool.tool)
    assert registry.get("log_search") is mock_tool.tool
    assert ToolRegistry().list() == ()


@pytest.mark.parametrize("name", ["missing", "rm -rf /", "python -c print(1)"])
def test_unknown_names_are_not_executed(mock_tool: MockTool, name: str) -> None:
    registry = ToolRegistry()
    registry.register(mock_tool.tool)
    assert name not in registry
    with pytest.raises(ToolNotFoundError):
        registry.get(name)
    assert mock_tool.call_count == 0


@pytest.mark.parametrize("candidate", [object(), {}, lambda: None])
def test_arbitrary_objects_rejected(candidate: object) -> None:
    registry = ToolRegistry()
    with pytest.raises(ToolRegistrationError):
        registry.register(candidate)
    assert registry.list() == ()


def test_invalid_schema_and_sync_handler_rejected(mock_tool: MockTool) -> None:
    tool = mock_tool.tool
    with pytest.raises(ToolRegistrationError):
        Tool(tool.metadata, str, tool.output_model, tool.handler)
    with pytest.raises(ToolRegistrationError):
        Tool(tool.metadata, tool.input_model, tool.output_model, lambda data: {})


@pytest.mark.asyncio
async def test_registered_execution_returns_result(mock_tool: MockTool) -> None:
    registry = ToolRegistry()
    registry.register(mock_tool.tool)
    result = await registry.get("log_search").execute({"query": "login"})
    assert result.tool_name == "log_search"
    assert result.output.matches == ["first"]
    assert result.model_dump(mode="json") == {
        "tool_name": "log_search",
        "output": {"matches": ["first"]},
    }
