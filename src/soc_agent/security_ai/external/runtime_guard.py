"""Persistent incident disposition plus opaque, task-local handler dispatch permits.

Trusted Python adapters remain part of the TCB; hostile executable code needs OS
process isolation. JSON/model output never creates an issuer or dispatch permit.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from time import monotonic
from uuid import UUID, uuid4

from pydantic import BaseModel

from soc_agent.execution import ActionProposal
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.security_ai.external.read_only_backend import CapabilityDenied, ReadOnlyCapability
from soc_agent.security_ai.external.runtime_store import (
    RuntimeBinding,
    RuntimeGovernanceStore,
    RuntimeRequirement,
    audit,
)
from soc_agent.security_ai.external.storage import ExternalContextStore
from soc_agent.tools import Tool, ToolRegistry


@dataclass(frozen=True)
class Grant:
    cap: ReadOnlyCapability
    binding: RuntimeBinding
    deadline: float


@dataclass
class Permit:
    tool: Tool
    action: ActionProposal
    payload_digest: str | None = None


class RuntimeBoundary:
    def __init__(self, store: RuntimeGovernanceStore, registry: ToolRegistry) -> None:
        if store.boundary is not None or registry.execution_guard is not None:
            raise ValueError("Backend security binding cannot be replaced")
        self.store, self.registry = store, registry
        self.contexts = ExternalContextStore(store.database.path, database=store.database)
        self._frame: ContextVar[Grant | None] = ContextVar("soc_read_only_grant", default=None)
        self._permit: ContextVar[Permit | None] = ContextVar("soc_handler_permit", default=None)
        self._issued: dict[UUID, Grant] = {}
        self._tools = {}
        self.assessment_requests: dict[UUID, tuple[str, str]] = {}
        store.boundary = self
        registry.execution_guard = self
        for metadata in registry.list():
            self.bind_tool(registry.get(metadata.name))

    def binding(self, incident_id: UUID) -> RuntimeBinding | None:
        with self.store.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM external_runtime_incidents WHERE incident_id=?", (str(incident_id),)
            ).fetchone()
            if row is None:
                if connection.execute(
                    "SELECT 1 FROM external_runtime_requirements WHERE incident_id=?",
                    (str(incident_id),),
                ).fetchone():
                    raise StoredDataError("Required external inference/context unavailable")
                if connection.execute(
                    "SELECT 1 FROM external_contexts WHERE incident_id=?", (str(incident_id),)
                ).fetchone():
                    raise StoredDataError("Required runtime binding missing")
                return None
            requirement_row = connection.execute(
                "SELECT * FROM external_runtime_requirements WHERE incident_id=?",
                (str(incident_id),),
            ).fetchone()
            requirement = (
                ledger.decode(RuntimeRequirement, requirement_row)
                if requirement_row is not None
                else None
            )
            if requirement is not None and (
                requirement.incident_id != incident_id or requirement.status != "ATTACHED"
            ):
                raise StoredDataError("External inference requirement mismatch")
            value = ledger.decode(RuntimeBinding, row)
            if str(value.incident_id) != row["incident_id"]:
                raise StoredDataError("Runtime incident binding mismatch")
            # A recomputed row digest is insufficient: the issued binding must be anchored in audit.
            last = connection.execute(
                "SELECT payload FROM external_security_audit "
                "WHERE json_extract(payload,'$.incident_id')=? "
                "AND json_extract(payload,'$.code') IN ('SESSION_ISSUED','CONTEXT_ATTACHED') "
                "ORDER BY sequence DESC LIMIT 1",
                (str(incident_id),),
            ).fetchone()
            import json

            anchor = json.loads(last[0]).get("binding_digest") if last is not None else None
            if anchor != row["digest"]:
                raise StoredDataError("Runtime binding audit mismatch")
        context = self.contexts.load_context(value.context_digest)
        if context.input_snapshot.incident_id != incident_id:
            raise StoredDataError("Context belongs to another incident")
        if requirement is not None and not set(requirement.required_models).issubset(
            result.binding.binding_id for result in context.results
        ):
            raise StoredDataError("Required external model result missing")
        return value

    def reject(self, code: str, binding: RuntimeBinding | None = None) -> None:
        with self.store.database.transaction() as connection:
            audit(connection, code, binding)
        raise CapabilityDenied(f"Backend read-only boundary denied: {code}") from None

    def attach(self, context) -> None:
        # Used by trusted ingestion/inference composition, never by a model proposal.
        names = tuple(m.name for m in self.registry.list() if m.is_read_only_capability)
        if not names:
            raise ValueError("Explicit read-only catalog required")
        binding = RuntimeBinding(
            incident_id=context.input_snapshot.incident_id,
            context_digest=context.context_digest,
            session_id=uuid4(),
            allowed_tools=names,
        )
        with self.store.database.transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM workflow_checkpoints WHERE incident_id=?",
                (str(binding.incident_id),),
            ).fetchone():
                raise StoredDataError("Context replacement requires a new reconciled workflow")
            from soc_agent.review.persistence.session import GovernanceSession

            if (
                GovernanceSession(connection, self.store.store_id).load(binding.incident_id).anchor
                != context.input_snapshot
            ):
                raise StoredDataError("Inference source snapshot changed before attachment")
            self.contexts._save_context(connection, context)
            connection.execute(
                "INSERT INTO external_runtime_incidents VALUES (?,?,?)",
                (str(binding.incident_id), ledger.serialize(binding), content_digest(binding)),
            )
            requirement_row = connection.execute(
                "SELECT * FROM external_runtime_requirements WHERE incident_id=?",
                (str(binding.incident_id),),
            ).fetchone()
            if requirement_row is not None:
                requirement = ledger.decode(RuntimeRequirement, requirement_row)
                attached = requirement.model_copy(update={"status": "ATTACHED"})
                connection.execute(
                    "UPDATE external_runtime_requirements SET payload=?,digest=? "
                    "WHERE incident_id=?",
                    (
                        ledger.serialize(attached),
                        content_digest(attached),
                        str(binding.incident_id),
                    ),
                )
            audit(connection, "CONTEXT_ATTACHED", binding, binding_digest=content_digest(binding))

    def issue(self, incident_id: UUID) -> Grant | None:
        binding = self.binding(incident_id)
        if binding is None:
            return None
        with self.store.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM external_runtime_incidents WHERE incident_id=?", (str(incident_id),)
            ).fetchone()
            if ledger.decode(RuntimeBinding, row) != binding:
                raise StoredDataError("Concurrent session binding changed")
            binding = binding.model_copy(update={"session_id": uuid4()})
            connection.execute(
                "UPDATE external_runtime_incidents SET payload=?,digest=? WHERE incident_id=?",
                (ledger.serialize(binding), content_digest(binding), str(incident_id)),
            )
            audit(connection, "SESSION_ISSUED", binding, binding_digest=content_digest(binding))
        grant = Grant(object.__new__(ReadOnlyCapability), binding, monotonic() + 300)
        self._issued[incident_id] = grant
        return grant

    @contextmanager
    def scope(self, incident_id: UUID, grant: Grant | None) -> Iterator[None]:
        binding = self.binding(incident_id)
        if binding is None:
            if grant is not None:
                self.reject("CROSS_INCIDENT")
            yield
            return
        if (
            grant is None
            or self._issued.get(incident_id) is not grant
            or type(grant.cap) is not ReadOnlyCapability
            or grant.binding != binding
            or monotonic() >= grant.deadline
        ):
            self.reject("CAPABILITY_INVALID", binding)
        token = self._frame.set(grant)
        try:
            yield
        finally:
            self._frame.reset(token)

    def mutation(self, incident_id: UUID | None, code: str) -> None:
        frame = self._frame.get()
        if frame is not None:
            self.reject(code, frame.binding)
        if incident_id is not None:
            binding = self.binding(incident_id)
            if binding is not None:
                self.reject(code, binding)
        else:
            with self.store.database.transaction(write=False) as connection:
                protected = connection.execute(
                    "SELECT 1 FROM external_runtime_incidents UNION "
                    "SELECT 1 FROM external_runtime_requirements LIMIT 1"
                ).fetchone()
            if protected:
                self.reject(code)

    def action(self, action: object, operation: str) -> None:
        if type(action) is not ActionProposal:
            self.reject("ACTION_TYPE")
        action = ActionProposal.model_validate_json(action.model_dump_json())
        binding = self.binding(action.incident_id)
        frame = self._frame.get()
        if frame is not None and frame.binding.incident_id != action.incident_id:
            self.reject("CROSS_INCIDENT", frame.binding)
        if binding is None:
            return
        if operation != "EXECUTE":
            self.reject("APPROVAL_REPLAY", binding)
        if (
            frame is None
            or self._issued.get(action.incident_id) is not frame
            or frame.binding != binding
            or monotonic() >= frame.deadline
        ):
            self.reject("CAPABILITY_MISSING", binding)
        tool = self.registry.get(action.tool_name)
        if (
            action.tool_name not in binding.allowed_tools
            or not tool.metadata.is_read_only_capability
        ):
            self.reject("WRITE_DENIED", binding)
        self._check_tool(tool)

    def planning_allowed(self, incident_id: UUID, metadata) -> bool:
        binding = self.binding(incident_id)
        return binding is None or (
            metadata.name in binding.allowed_tools and metadata.is_read_only_capability
        )

    def _check_tool(self, tool: Tool) -> None:
        saved = self._tools.get(id(tool))
        if saved is None or saved != (
            tool.metadata.model_dump_json(),
            tool.input_model,
            tool.output_model,
            tool.handler,
        ):
            self.reject(
                "TOOL_REGISTRY_CHANGED", self._frame.get().binding if self._frame.get() else None
            )
        if self.registry.get(tool.metadata.name) is not tool or tool.execution_guard is not self:
            self.reject("TOOL_ALIAS", self._frame.get().binding if self._frame.get() else None)

    def bind_tool(self, tool: Tool) -> None:
        if type(tool) is not Tool or tool.execution_guard is not None:
            raise ValueError("Only unbound exact trusted Tool instances may be registered")
        original = tool.handler

        async def guarded(value):
            self.before_handler(tool, value)
            return await original(value)

        object.__setattr__(tool, "handler", guarded)
        object.__setattr__(tool, "execution_guard", self)
        self._tools[id(tool)] = (
            tool.metadata.model_dump_json(),
            tool.input_model,
            tool.output_model,
            guarded,
        )

    @contextmanager
    def dispatch(self, action: ActionProposal, tool: Tool) -> Iterator[None]:
        self.action(action, "EXECUTE")
        self._check_tool(tool)
        token = self._permit.set(Permit(tool, action))
        try:
            yield
        finally:
            self._permit.reset(token)

    def before_tool(self, tool: Tool) -> None:
        permit = self._permit.get()
        if permit is None or permit.tool is not tool:
            self.reject(
                "DIRECT_HANDLER_DENIED", self._frame.get().binding if self._frame.get() else None
            )
        self.action(permit.action, "EXECUTE")
        self._check_tool(tool)

    def before_handler(self, tool: Tool, value: BaseModel) -> None:
        self.before_tool(tool)
        permit = self._permit.get()
        binding = self.binding(permit.action.incident_id)
        target_incident = getattr(value, "incident_id", None)
        if (
            binding is not None
            and target_incident is not None
            and target_incident != binding.incident_id
        ):
            self.reject("TOOL_INPUT_INCIDENT_MISMATCH", binding)
        digest = content_digest(value)
        # Normalize with the exact trusted input schema, including defaults/coercion.
        expected = tool.input_model.model_validate(permit.action.input_payload(), extra="forbid")
        if digest != content_digest(expected) or (
            permit.payload_digest is not None and permit.payload_digest != digest
        ):
            self.reject("HANDLER_PAYLOAD_CHANGED")
        permit.payload_digest = digest
