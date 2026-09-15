"""Deterministic adapter with isolated response queues and validated request history."""

from collections import deque
from collections.abc import Sequence
from copy import deepcopy

from pydantic import BaseModel, JsonValue

from soc_agent.security_ai.base import SecurityAI
from soc_agent.security_ai.errors import SecurityAIMockExhaustedError
from soc_agent.security_ai.models import SecurityAIModelMetadata, SecurityAIRequest


class MockSecurityAI[TInput: BaseModel]:
    """Register mock.model, just as Tool fixtures expose mock.tool.

    Only validated requests reaching inference count. Invalid output, configured
    failures, and exhaustion count; invalid input does not consume a response.
    History is copied test instrumentation, not production storage or an audit log.
    """

    def __init__(
        self,
        *,
        metadata: SecurityAIModelMetadata,
        input_model: type[TInput],
        responses: Sequence[JsonValue | Exception],
    ) -> None:
        self._responses = deque(deepcopy(list(responses)))
        self._requests: list[SecurityAIRequest[TInput]] = []
        self._model = SecurityAI(metadata, input_model, self._predict)

    @property
    def model(self) -> SecurityAI[TInput]:
        return self._model

    @property
    def requests(self) -> tuple[SecurityAIRequest[TInput], ...]:
        return tuple(request.model_copy(deep=True) for request in self._requests)

    @property
    def call_count(self) -> int:
        return len(self._requests)

    async def _predict(self, request: SecurityAIRequest[TInput]) -> object:
        self._requests.append(request.model_copy(deep=True))
        if not self._responses:
            raise SecurityAIMockExhaustedError("No configured model responses remain")
        response = self._responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response
