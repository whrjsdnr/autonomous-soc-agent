"""Deterministic adapter composed with the same boundary as future tools."""

from collections import deque
from collections.abc import Sequence
from copy import deepcopy

from pydantic import BaseModel, JsonValue

from soc_agent.tools.base import Tool
from soc_agent.tools.errors import ToolMockExhaustedError
from soc_agent.tools.models import ToolMetadata


class MockTool[TInput: BaseModel, TOutput: BaseModel]:
    """Use mock.tool for registration or execution through validation.

    Responses may contain exceptions to simulate implementation failures.
    Only inputs that reach the implementation are recorded. Failed output and
    exhaustion attempts count; invalid inputs neither count nor consume responses.
    History is copied test instrumentation, not an audit log.
    """

    def __init__(
        self,
        *,
        metadata: ToolMetadata,
        input_model: type[TInput],
        output_model: type[TOutput],
        responses: Sequence[JsonValue | Exception],
    ) -> None:
        self._responses = deque(deepcopy(list(responses)))
        self._inputs: list[TInput] = []
        self._tool = Tool(metadata, input_model, output_model, self._execute)

    @property
    def tool(self) -> Tool[TInput, TOutput]:
        return self._tool

    @property
    def received_inputs(self) -> tuple[TInput, ...]:
        return tuple(item.model_copy(deep=True) for item in self._inputs)

    @property
    def call_count(self) -> int:
        return len(self._inputs)

    async def _execute(self, input_data: TInput) -> object:
        self._inputs.append(input_data.model_copy(deep=True))
        if not self._responses:
            raise ToolMockExhaustedError("No configured tool responses remain")
        response = self._responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response
