"""Deterministic in-memory client for future agent tests."""

from collections import deque
from collections.abc import Sequence
from copy import deepcopy

from pydantic import BaseModel, JsonValue

from soc_agent.llm.client import validate_response
from soc_agent.llm.errors import LLMMockExhaustedError
from soc_agent.llm.models import LLMRequest


class MockLLMClient:
    """Consume one decoded JSON response per call, including invalid responses.

    Inputs are copied so changes to fixtures cannot change queued responses.
    Every attempt is recorded, including validation failures and exhaustion.
    Request history is test instrumentation, not an incident state or audit log.
    """

    def __init__(self, responses: Sequence[JsonValue]) -> None:
        self._responses = deque(deepcopy(list(responses)))
        self._requests: list[LLMRequest] = []

    @property
    def requests(self) -> tuple[LLMRequest, ...]:
        return tuple(self._requests)

    @property
    def call_count(self) -> int:
        return len(self._requests)

    async def generate_structured[T: BaseModel](
        self, *, request: LLMRequest, response_model: type[T]
    ) -> T:
        self._requests.append(request)
        if not self._responses:
            raise LLMMockExhaustedError("No configured LLM responses remain")
        return validate_response(self._responses.popleft(), response_model)
