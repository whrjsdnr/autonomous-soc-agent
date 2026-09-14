"""Explicit execution allowlist populated by trusted application setup."""

from typing import cast

from pydantic import BaseModel

from soc_agent.tools.base import Tool
from soc_agent.tools.errors import ToolNotFoundError, ToolRegistrationError
from soc_agent.tools.models import ToolMetadata


class ToolRegistry:
    """Only validated Tool wrappers may be registered; names never overwrite.

    Registration is a trusted setup operation, not an LLM-accessible capability.
    Membership does not substitute for future policy or human authorization.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool[BaseModel, BaseModel]] = {}

    def register[I: BaseModel, O: BaseModel](self, tool: Tool[I, O]) -> None:
        if type(tool) is not Tool:
            raise ToolRegistrationError("Register a Tool wrapper, not an arbitrary implementation")
        name = tool.metadata.name
        if name in self._tools:
            raise ToolRegistrationError("Tool name is already registered")
        # Heterogeneous lookup erases schema types; the wrapper validates at runtime.
        self._tools[name] = cast(Tool[BaseModel, BaseModel], tool)

    def get(self, name: str) -> Tool[BaseModel, BaseModel]:
        try:
            return self._tools[name]
        except KeyError as error:
            raise ToolNotFoundError("Tool name is not registered") from error

    def list(self) -> tuple[ToolMetadata, ...]:
        return tuple(tool.metadata for tool in self._tools.values())

    def __contains__(self, name: str) -> bool:
        return name in self._tools
