"""Explicit model allowlist, populated only by trusted application setup."""

from typing import cast

from pydantic import BaseModel

from soc_agent.security_ai.base import SecurityAI
from soc_agent.security_ai.errors import SecurityAILookupError, SecurityAIRegistrationError
from soc_agent.security_ai.models import SecurityAIModelMetadata


class SecurityAIRegistry:
    """Name-only keys; one version per name, no replacement or fallback routing."""

    def __init__(self) -> None:
        self._models: dict[str, SecurityAI[BaseModel]] = {}

    def register[I: BaseModel](self, model: SecurityAI[I]) -> None:
        if type(model) is not SecurityAI:
            raise SecurityAIRegistrationError("Register a SecurityAI wrapper, not a raw handler")
        name = model.metadata.name
        if name in self._models:
            raise SecurityAIRegistrationError("Model name is already registered")
        # The heterogeneous registry erases static schema types; wrappers validate at runtime.
        self._models[name] = cast(SecurityAI[BaseModel], model)

    def get(self, name: str) -> SecurityAI[BaseModel]:
        try:
            return self._models[name]
        except KeyError as error:
            raise SecurityAILookupError("Model name is not registered") from error

    def list(self) -> tuple[SecurityAIModelMetadata, ...]:
        return tuple(model.metadata for model in self._models.values())

    def __contains__(self, name: str) -> bool:
        return name in self._models
