"""Small validation wrapper composed with a trusted async implementation."""

from collections.abc import Mapping
from dataclasses import dataclass
from inspect import iscoroutinefunction
from typing import Protocol

from pydantic import BaseModel, ValidationError

from soc_agent.tools.errors import (
    ToolExecutionError,
    ToolInputValidationError,
    ToolOutputValidationError,
    ToolRegistrationError,
)
from soc_agent.tools.models import ToolMetadata, ToolResult


class ToolHandler[TInput: BaseModel](Protocol):
    """Trusted adapter receiving validated input; its output is still untrusted."""

    async def __call__(self, input_data: TInput) -> object: ...


@dataclass(frozen=True)
class Tool[TInput: BaseModel, TOutput: BaseModel]:
    """Validated execution boundary, without policy, retries, or external I/O.

    Only trusted application setup constructs tools and supplies implementations.
    Frozen configuration prevents ordinary identity changes after registration.
    This wrapper is not a sandbox for malicious Python code.
    """

    metadata: ToolMetadata
    input_model: type[TInput]
    output_model: type[TOutput]
    handler: ToolHandler[TInput]

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, ToolMetadata):
            raise ToolRegistrationError("Tool metadata must be ToolMetadata")
        try:
            ToolMetadata.model_validate(self.metadata.model_dump(warnings=False))
        except ValidationError as error:
            raise ToolRegistrationError("Invalid tool metadata") from error
        for schema in (self.input_model, self.output_model):
            if not isinstance(schema, type) or not issubclass(schema, BaseModel):
                raise ToolRegistrationError("Tool schemas must be Pydantic model classes")
        if not callable(self.handler) or not (
            iscoroutinefunction(self.handler) or iscoroutinefunction(self.handler.__call__)
        ):
            raise ToolRegistrationError("Tool handler must be async")

    async def execute(self, raw_input: Mapping[str, object] | TInput) -> ToolResult[TOutput]:
        """Validate both sides, including model instances that may have been mutated.

        Extra fields are rejected; field coercion follows the supplied schema.
        Cancellation and other BaseExceptions propagate unchanged.
        """
        try:
            # Revalidation below reports invalid model values as boundary errors.
            payload = (
                raw_input.model_dump(warnings=False)
                if isinstance(raw_input, BaseModel)
                else raw_input
            )
            validated_input = self.input_model.model_validate(payload, extra="forbid")
        except ValidationError as error:
            raise ToolInputValidationError("Tool input does not match its schema") from error
        try:
            output = await self.handler(validated_input)
        except ToolExecutionError:
            raise
        except Exception as error:
            # Adapter failures are intentionally translated, never silently swallowed.
            raise ToolExecutionError("Tool implementation failed") from error
        try:
            payload = output.model_dump(warnings=False) if isinstance(output, BaseModel) else output
            validated_output = self.output_model.model_validate(payload, extra="forbid")
        except ValidationError as error:
            raise ToolOutputValidationError("Tool output does not match its schema") from error
        return ToolResult[self.output_model](tool_name=self.metadata.name, output=validated_output)
