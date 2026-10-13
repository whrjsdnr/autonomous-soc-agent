"""Scoped offline execution port; not a global Python sandbox or runtime activation.

Only trusted composition may call the factory. Never expose it, the source registry,
or legacy executors to an untrusted client. Handles confer authority only at the
issuing port, never when deserialized or passed to existing legacy APIs.
"""

from collections import deque
from dataclasses import dataclass
from math import isfinite
from time import monotonic
from uuid import UUID, uuid4

from pydantic import BaseModel, ValidationError

from soc_agent.approval import ApprovalManager
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.policy import PolicyEngine
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.external.records import ResumeRequirement
from soc_agent.security_ai.external.storage import ExternalContextStore
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry, ToolResult
from soc_agent.tools.errors import ToolNotFoundError


class CapabilityDenied(ExecutionDeniedError):
    """Sanitized denial; no context, credentials or action input in the message."""


class ReadOnlyCapability:
    """Opaque non-serializable identity, with no writable fields or authority claims."""

    __slots__ = ()

    def __new__(cls):
        raise TypeError("Only the trusted backend factory issues capabilities")

    def __reduce_ex__(self, protocol):
        raise TypeError("Capabilities cannot be serialized or copied")


@dataclass(frozen=True, slots=True)
class SecurityRejection:
    sequence: int
    session_id: UUID
    code: str


@dataclass(frozen=True, slots=True)
class _Grant:
    requirement: ResumeRequirement
    session_id: UUID
    expires: float
    names: tuple[str, ...]


class ReadOnlyBackend:
    """Bound execution service. Its trusted issuer state is not caller JSON.

    Rejection history is a bounded process-local security journal, separate from
    the existing durable audit. Durable publication is deliberately not claimed.
    Losing the process invalidates every handle; restart requires a fresh issuer
    after validating persisted lineage. No approval or promotion API is exposed.
    """

    def __init__(self):
        raise TypeError("Use the trusted backend factory")

    def _deny(self, code: str) -> None:
        self._sequence += 1
        self._events.append(SecurityRejection(self._sequence, self._grant.session_id, code))
        raise CapabilityDenied(f"Read-only capability denied: {code}") from None

    @property
    def security_events(self) -> tuple[SecurityRejection, ...]:
        return tuple(self._events)

    @property
    def session_id(self) -> UUID:
        return self._grant.session_id

    def close(self) -> None:
        self._closed = True

    def _validate(
        self,
        capability: object,
        *,
        incident_id: UUID,
        session_id: UUID,
        context_digest: str,
        contract_version: str,
    ) -> None:
        if (
            self._closed
            or type(capability) is not ReadOnlyCapability
            or capability is not self._cap
        ):
            self._deny("UNISSUED_OR_CLOSED")
        grant = self._grant
        if monotonic() >= grant.expires:
            self._deny("EXPIRED")
        if (
            incident_id != grant.requirement.incident_id
            or session_id != grant.session_id
            or context_digest != grant.requirement.context_digest
            or contract_version != "soc-external-model-context:v2"
        ):
            self._deny("IDENTITY_BINDING")
        try:
            self._store.resume(grant.requirement)
        except (StorageError, ValueError):
            self._deny("PERSISTED_LINEAGE")
        for name, tool, metadata, handler, input_model, output_model in self._tools:
            try:
                current = self._source.get(name)
            except ToolNotFoundError:
                self._deny("REGISTRY_CHANGED")
            if (
                current is not tool
                or type(tool) is not Tool
                or tool.metadata != metadata
                or tool.handler is not handler
                or tool.input_model is not input_model
                or tool.output_model is not output_model
            ):
                self._deny("REGISTRY_CHANGED")

    async def execute(
        self,
        action: ActionProposal,
        *,
        capability: object = None,
        session_id: UUID | None = None,
        context_digest: str = "",
        contract_version: str = "",
        approval_id: UUID | None = None,
    ) -> ToolResult[BaseModel]:
        # Validate issuance before inspecting any untrusted action payload.
        self._validate(
            capability,
            incident_id=self._grant.requirement.incident_id,
            session_id=session_id,
            context_digest=context_digest,
            contract_version=contract_version,
        )
        if type(action) is not ActionProposal:
            self._deny("ACTION_TYPE")
        try:
            action = ActionProposal.model_validate_json(action.model_dump_json())
        except (ValidationError, ValueError):
            self._deny("ACTION_INVALID")
        if action.incident_id != self._grant.requirement.incident_id:
            self._deny("ACTION_INCIDENT")
        if approval_id is not None:
            self._deny("APPROVAL_NOT_A_CAPABILITY")
        if action.tool_name not in self._grant.names:
            self._deny("TOOL_NOT_ALLOWED")
        if self._attempts >= 128:
            self._deny("SESSION_BUDGET")
        self._attempts += 1
        # No await occurs between revalidation, legacy policy enforcement and the
        # actual Tool handler. Trusted handlers remain responsible for read-only I/O.
        return await self._executor.execute(action, require_read_only=True)

    def __reduce_ex__(self, protocol):
        raise TypeError("Backend issuers cannot be serialized or copied")


def open_read_only_backend(
    *,
    store: ExternalContextStore,
    requirement: ResumeRequirement,
    registry: ToolRegistry,
    allowed_tools: tuple[str, ...],
    lifetime_seconds: float = 60,
) -> tuple[ReadOnlyBackend, ReadOnlyCapability]:
    """Trusted composition-only factory, not an event/LLM/API request endpoint.

    Caller supplies an already established persisted receipt, not a model's claim
    to be VALID. No promotion, approval, policy editing or WRITE handler is wired.
    """
    if type(store) is not ExternalContextStore or type(registry) is not ToolRegistry:
        raise CapabilityDenied("Invalid trusted backend dependencies")
    if (
        type(lifetime_seconds) not in (int, float)
        or not isfinite(lifetime_seconds)
        or not 0 < lifetime_seconds <= 300
        or type(allowed_tools) is not tuple
        or not allowed_tools
        or len(allowed_tools) > 32
        or any(type(name) is not str for name in allowed_tools)
        or len(set(allowed_tools)) != len(allowed_tools)
    ):
        raise CapabilityDenied("Invalid bounded read-only configuration")
    requirement = ResumeRequirement.model_validate_json(requirement.model_dump_json())
    store.resume(requirement)
    copied = ToolRegistry()
    snapshots = []
    for name in allowed_tools:
        tool = registry.get(name)
        metadata = ToolMetadata.model_validate_json(tool.metadata.model_dump_json())
        if type(tool) is not Tool or metadata.name != name or not metadata.is_read_only_capability:
            raise CapabilityDenied("Only exact registered read-only tools may be granted")
        copied.register(tool)
        snapshots.append((name, tool, metadata, tool.handler, tool.input_model, tool.output_model))
    backend = object.__new__(ReadOnlyBackend)
    capability = object.__new__(ReadOnlyCapability)
    backend._grant = _Grant(requirement, uuid4(), monotonic() + lifetime_seconds, allowed_tools)
    backend._cap, backend._store, backend._source = capability, store, registry
    backend._tools, backend._closed, backend._attempts = tuple(snapshots), False, 0
    backend._events, backend._sequence = deque(maxlen=128), 0
    backend._executor = GovernedExecutor(
        registry=copied, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    return backend, capability
