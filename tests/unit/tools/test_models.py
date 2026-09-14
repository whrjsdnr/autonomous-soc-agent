from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError

from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRiskLevel


@pytest.mark.parametrize("risk", list(ToolRiskLevel))
@pytest.mark.parametrize("permission", list(ToolPermission))
def test_enum_serialization(
    metadata: ToolMetadata, risk: ToolRiskLevel, permission: ToolPermission
) -> None:
    data = metadata.model_dump() | {"risk_level": risk.value, "permission": permission.value}
    model = ToolMetadata.model_validate(data)
    assert model.risk_level is risk
    assert model.permission is permission
    assert model.model_dump(mode="json")["risk_level"] == risk.value


@pytest.mark.parametrize(
    "update",
    [
        {"name": ""},
        {"name": "BadName"},
        {"name": "log__search"},
        {"name": "log_search\n"},
        {"name": "rm -rf /"},
        {"name": "_hidden"},
        {"name": "log-search"},
        {"description": "  "},
        {"permission": "root"},
        {"risk_level": "safe"},
        {"extra": True},
    ],
)
def test_invalid_metadata(metadata: ToolMetadata, update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ToolMetadata.model_validate(metadata.model_dump() | update)


def test_configuration_is_immutable(mock_tool: MockTool) -> None:
    with pytest.raises(ValidationError):
        mock_tool.tool.metadata.name = "renamed"
    with pytest.raises(FrozenInstanceError):
        mock_tool.tool.metadata = mock_tool.tool.metadata
