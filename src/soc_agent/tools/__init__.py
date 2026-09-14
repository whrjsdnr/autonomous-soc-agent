"""Validated tool capabilities and an explicit registration allowlist."""

from soc_agent.tools.base import Tool, ToolHandler
from soc_agent.tools.enums import ToolPermission, ToolRiskLevel
from soc_agent.tools.errors import (
    ToolError,
    ToolExecutionError,
    ToolInputValidationError,
    ToolMockExhaustedError,
    ToolNotFoundError,
    ToolOutputValidationError,
    ToolRegistrationError,
)
from soc_agent.tools.mock import MockTool
from soc_agent.tools.models import ToolMetadata, ToolResult
from soc_agent.tools.registry import ToolRegistry

__all__ = [
    "MockTool",
    "Tool",
    "ToolError",
    "ToolExecutionError",
    "ToolHandler",
    "ToolInputValidationError",
    "ToolMetadata",
    "ToolMockExhaustedError",
    "ToolNotFoundError",
    "ToolOutputValidationError",
    "ToolPermission",
    "ToolRegistrationError",
    "ToolRegistry",
    "ToolResult",
    "ToolRiskLevel",
]
