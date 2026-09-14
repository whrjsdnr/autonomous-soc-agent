import pytest
from pydantic import BaseModel, ConfigDict, JsonValue

from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class SearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    limit: int = 10


class SearchOutput(BaseModel):
    count: int


@pytest.fixture
def mock_tool() -> MockTool[SearchInput, SearchOutput]:
    return MockTool(
        metadata=ToolMetadata(
            name="search_auth_logs",
            description="Search authentication logs",
            permission=ToolPermission.FILE_READ,
            risk_level=ToolRiskLevel.READ_ONLY,
        ),
        input_model=SearchInput,
        output_model=SearchOutput,
        responses=[{"count": 12}],
    )


@pytest.fixture
def registry(mock_tool: MockTool) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(mock_tool.tool)
    return registry


@pytest.fixture
def response() -> dict[str, JsonValue]:
    return {
        "goal": "Investigate authentication",
        "steps": [
            {
                "tool_name": "search_auth_logs",
                "tool_input": {"username": "alice"},
                "purpose": "Inspect login failures",
            }
        ],
    }
