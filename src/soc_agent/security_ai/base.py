"""Trusted inference wrapper owning validation and provenance binding."""

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from inspect import iscoroutinefunction
from typing import Protocol

from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticSerializationError

from soc_agent.security_ai.errors import (
    SecurityAIInferenceError,
    SecurityAIInputValidationError,
    SecurityAIOutputValidationError,
    SecurityAIRegistrationError,
)
from soc_agent.security_ai.models import (
    SecurityAIModelMetadata,
    SecurityAIPrediction,
    SecurityAIRequest,
    SecurityAIResult,
)


class SecurityAIHandler[TInput: BaseModel](Protocol):
    """Adapter receives minimal validated context and returns only prediction data."""

    async def __call__(self, request: SecurityAIRequest[TInput]) -> object: ...


@dataclass(frozen=True)
class SecurityAI[TInput: BaseModel]:
    """Composition with a trusted adapter; no LLM, tools, state changes, or retries.

    This is a contract, not a sandbox for malicious Python handlers. Trusted setup
    registers wrappers and keeps raw adapters out of future agent-facing APIs.
    """

    metadata: SecurityAIModelMetadata
    input_model: type[TInput]
    handler: SecurityAIHandler[TInput]

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, SecurityAIModelMetadata):
            raise SecurityAIRegistrationError("Model metadata must be SecurityAIModelMetadata")
        try:
            metadata = SecurityAIModelMetadata.model_validate(
                self.metadata.model_dump(warnings=False)
            )
        except ValidationError as error:
            raise SecurityAIRegistrationError("Invalid model metadata") from error
        # Detach from any caller-owned instance, including subclasses.
        object.__setattr__(self, "metadata", metadata)
        if not isinstance(self.input_model, type) or not issubclass(self.input_model, BaseModel):
            raise SecurityAIRegistrationError("Input schema must be a Pydantic model class")
        if not callable(self.handler) or not (
            iscoroutinefunction(self.handler) or iscoroutinefunction(self.handler.__call__)
        ):
            raise SecurityAIRegistrationError("Inference handler must be async")

    async def predict(
        self,
        request: Mapping[str, object] | SecurityAIRequest[TInput],
    ) -> SecurityAIResult:
        """Reject invalid input before calling the handler; preserve cancellation."""
        try:
            payload = (
                request.model_dump(by_alias=True, warnings=False)
                if isinstance(request, BaseModel)
                else dict(request)
            )
            # A raw envelope may contain an already constructed (possibly invalid) input model.
            value = payload.get("input")
            if isinstance(value, BaseModel):
                payload["input"] = value.model_dump(by_alias=True, warnings=False)
            validated = SecurityAIRequest[self.input_model].model_validate(
                deepcopy(payload),
                extra="forbid",
            )
        except (ValueError, TypeError, PydanticSerializationError) as error:
            raise SecurityAIInputValidationError(
                "Request does not match the model input schema"
            ) from error
        incident_id = validated.incident_id
        metadata = self.metadata
        try:
            output = await self.handler(validated)
        except SecurityAIInferenceError:
            raise
        except Exception as error:
            raise SecurityAIInferenceError("Model inference failed") from error
        try:
            payload = output.model_dump(warnings=False) if isinstance(output, BaseModel) else output
            prediction = SecurityAIPrediction.model_validate(payload, extra="forbid")
        except (ValueError, TypeError, PydanticSerializationError) as error:
            raise SecurityAIOutputValidationError(
                "Model output does not match the prediction schema"
            ) from error
        return SecurityAIResult(
            incident_id=incident_id,
            model_name=metadata.name,
            model_version=metadata.version,
            task_type=metadata.task_type,
            **prediction.model_dump(),
        )
