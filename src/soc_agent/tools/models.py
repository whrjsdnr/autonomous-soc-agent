"""Immutable declarations and successful structured results."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from soc_agent.tools.enums import ToolPermission, ToolRiskLevel

ToolName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")]


class ToolMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: ToolName
    description: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    permission: ToolPermission
    risk_level: ToolRiskLevel

    @property
    def is_read_only_capability(self) -> bool:
        """Observation-only scope, independent of policy authorization."""
        return self.permission in (
            ToolPermission.SYSTEM_READ,
            ToolPermission.NETWORK_READ,
            ToolPermission.FILE_READ,
        ) and self.risk_level in (ToolRiskLevel.READ_ONLY, ToolRiskLevel.LOW)


class ToolResult[TOutput: BaseModel](BaseModel):
    """A successful result; failures are exceptions, not success=False payloads.

    Output mutability follows its schema. This is not evidence or incident state.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: ToolName
    output: TOutput
