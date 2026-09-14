"""Minimal structured generation contract and shared output validation."""

from typing import Protocol

from pydantic import BaseModel, JsonValue, ValidationError

from soc_agent.llm.errors import LLMResponseValidationError
from soc_agent.llm.models import LLMRequest


class LLMClient(Protocol):
    """Implementations validate output before returning and translate SDK failures.

    Return only the requested model, never raw output. Schema coercion and extra
    fields follow that model's Pydantic configuration. Cancellation must propagate.
    No automatic retries are implied by this contract.
    """

    async def generate_structured[T: BaseModel](
        self, *, request: LLMRequest, response_model: type[T]
    ) -> T: ...


def validate_response[T: BaseModel](payload: JsonValue, response_model: type[T]) -> T:
    """Validate decoded JSON at the boundary, shared by mock and future adapters."""
    try:
        return response_model.model_validate(payload)
    except ValidationError as error:
        # Avoid copying potentially sensitive response values into the public message.
        raise LLMResponseValidationError(
            "LLM response does not match the requested schema"
        ) from error
