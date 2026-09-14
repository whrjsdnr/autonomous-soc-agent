import pytest
from pydantic import BaseModel, ConfigDict

from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRiskLevel


class SearchInput(BaseModel):
    model_config = ConfigDict(strict=True)
    query: str


class SearchOutput(BaseModel):
    matches: list[str]


@pytest.fixture
def metadata() -> ToolMetadata:
    return ToolMetadata(
        name="log_search",
        description="Search fixture logs",
        permission=ToolPermission.FILE_READ,
        risk_level=ToolRiskLevel.READ_ONLY,
    )


@pytest.fixture
def mock_tool(metadata: ToolMetadata) -> MockTool[SearchInput, SearchOutput]:
    return MockTool(
        metadata=metadata,
        input_model=SearchInput,
        output_model=SearchOutput,
        responses=[{"matches": ["first"]}, {"matches": ["second"]}],
    )
