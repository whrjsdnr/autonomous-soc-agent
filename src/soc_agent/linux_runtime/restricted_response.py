"""Approved test-marker effects and rollback, using existing governance and audit.

Only the runtime's serialized operator endpoint invokes this trusted composition
root. Filesystem effects and SQLite commits are deliberately not claimed atomic.
"""

import hashlib
import inspect
import os
import socket
import struct
from asyncio.trsock import TransportSocket
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from uuid import NAMESPACE_URL, uuid5

from soc_agent.approval import ApprovalManager
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.binding import validate_binding
from soc_agent.execution.errors import ExecutionDeniedError, ExecutionError
from soc_agent.linux_runtime.restricted_models import (
    MarkerOutput,
    ResourceRegistration,
    RestrictedInput,
    RestrictedReceipt,
    RestrictedRecord,
)
from soc_agent.linux_runtime.restricted_resource import AVAILABLE, QUARANTINED, TestResource, digest
from soc_agent.policy import PolicyDecision, PolicyEngine
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry
from soc_agent.tools.errors import ToolError

if TYPE_CHECKING:
    from soc_agent.linux_runtime.response_simulation import RuntimeResponseSimulation
    from soc_agent.linux_runtime.service import LinuxMonitor
    from soc_agent.linux_runtime.store import RuntimeStore

PeerSocket = socket.socket | TransportSocket

NAME = "change_registered_test_marker"
METADATA = ToolMetadata(
    name=NAME,
    description="Approved private test marker only; no OS security action",
    permission="file_write",
    risk_level="high",
)


def authenticated_uid(sock: PeerSocket) -> int:
    if type(sock) not in (socket.socket, TransportSocket) or sock.family != socket.AF_UNIX:
        raise ExecutionDeniedError("RESTRICTED_OPERATOR_TRANSPORT_REJECTED")
    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        raise ExecutionDeniedError("RESTRICTED_OPERATOR_TRANSPORT_REJECTED")
    _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.geteuid():
        raise ExecutionDeniedError("RESTRICTED_OPERATOR_DENIED")
    return uid


class RestrictedDispatchGuard:
    def __init__(self, action: ActionProposal) -> None:
        self.expected = action
        self.tool = None
        self.authorization = ContextVar("restricted_dispatch", default=None)

    def planning_allowed(self, incident_id, metadata):
        return False

    def bind_tool(self, tool):
        if self.tool is not None or tool.metadata != METADATA:
            raise ExecutionDeniedError("RESTRICTED_TOOL_BINDING_REJECTED")
        self.tool = tool
        object.__setattr__(tool, "execution_guard", self)

    def action(self, action, operation):
        if action != self.expected:
            raise ExecutionDeniedError("RESTRICTED_EXACT_ACTION_REQUIRED")

    def before_tool(self, tool):
        if tool is not self.tool or self.authorization.get() != self.expected.action_id:
            raise ExecutionDeniedError("RESTRICTED_GOVERNED_DISPATCH_REQUIRED")

    def before_handler(self, tool, value):
        self.before_tool(tool)
        if value.model_dump(mode="json") != self.expected.input_payload():
            raise ExecutionDeniedError("RESTRICTED_INPUT_BINDING_REJECTED")

    @contextmanager
    def dispatch(self, action, tool):
        self.action(action, "EXECUTE")
        if tool is not self.tool:
            raise ExecutionDeniedError("RESTRICTED_DISPATCH_REJECTED")
        token = self.authorization.set(self.expected.action_id)
        try:
            yield
        finally:
            self.authorization.reset(token)


class RestrictedResponseExecutor:
    def __init__(
        self,
        monitor: "LinuxMonitor",
        *,
        policy: PolicyEngine | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.monitor, self.store = monitor, monitor.store
        self.resource = TestResource(monitor.directory)
        self.policy, self.clock = policy or PolicyEngine(), clock

    def _events(self, c):
        return self.monitor.simulation._events(c)

    def _mode(self, c):
        if any(e["kind"] == "RESTRICTED_RECOVERY_CONFLICT" for e in self._events(c)):
            raise ExecutionDeniedError("RESTRICTED_RESOURCE_REQUIRES_RECONCILIATION")
        entries = [e for e in self._events(c) if e["kind"] == "RESTRICTED_TEST_MODE"]
        if not entries:
            raise ExecutionDeniedError("RESTRICTED_DEFAULT_DENY")
        if len(entries) != 1 or entries[0]["details"]["test_mode"] is not True:
            raise ExecutionDeniedError("RESTRICTED_MODE_REJECTED")
        return ResourceRegistration.model_validate(entries[0]["details"]["registration"])

    def enable_test_mode(self, *, test_mode: bool) -> ResourceRegistration:
        """CLI-only offline preparation under the existing exclusive writer lock."""
        if (
            test_mode is not True
            or self.store.state()["state"] != "STOPPED"
            or self.monitor.config != self.store.config
        ):
            raise ExecutionDeniedError("RESTRICTED_OFFLINE_EXPLICIT_TEST_MODE_REQUIRED")
        self.store.verify_audit()
        with self.store.database.transaction() as c:
            if any(e["kind"] == "RESTRICTED_TEST_MODE" for e in self._events(c)):
                raise ExecutionDeniedError("RESTRICTED_MODE_ALREADY_REGISTERED")
            registration = self.resource.create()
            self.store._audit(
                c,
                "RESTRICTED_TEST_MODE",
                {
                    "test_mode": True,
                    "registration": registration.model_dump(mode="json"),
                    "automatic_approval": False,
                    "os_security_execution": "DISABLED",
                },
            )
        return registration

    def _runtime(self) -> None:
        state = self.store.state()
        if (
            state["state"] != "RUNNING"
            or state["stop_requested"]
            or self.monitor.stop_event.is_set()
        ):
            raise ExecutionDeniedError("RESTRICTED_RUNTIME_NOT_RUNNING")

    def _policy_digest(self) -> str:
        result = self.policy.evaluate(METADATA)
        if result.decision != PolicyDecision.REQUIRE_APPROVAL:
            raise ExecutionDeniedError("RESTRICTED_REQUIRE_APPROVAL_POLICY_REQUIRED")
        return content_digest_payload(
            {
                "metadata": METADATA.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
                "policy_type": type(self.policy).__module__ + "." + type(self.policy).__qualname__,
                "policy_implementation_digest": hashlib.sha256(
                    inspect.getsource(type(self.policy)).encode()
                ).hexdigest(),
            }
        )

    @staticmethod
    def read_records(events):
        """Validate the same append-only history for execution and read-only health."""
        records = {}
        allowed = {
            "PENDING_APPROVAL": {"APPROVED", "REJECTED"},
            "APPROVED": {"STARTED"},
            "STARTED": {"TEST_RESOURCE_CHANGED", "ROLLED_BACK", "UNKNOWN"},
        }
        for event in events:
            if event["kind"] != "RESTRICTED_RECORD":
                continue
            record = RestrictedRecord.model_validate(event["details"]["record"])
            value = RestrictedInput.model_validate(record.action.input_payload())
            if (
                record.candidate_id != content_digest_payload(value.model_dump(mode="json"))
                or record.action.action_id != uuid5(NAMESPACE_URL, record.candidate_id)
                or record.action.tool_name != NAME
            ):
                raise ValueError("RESTRICTED_RECORD_IDENTITY_REJECTED")
            validate_binding(record.action, record.approval, METADATA)
            expected_status = (
                "pending"
                if record.status == "PENDING_APPROVAL"
                else "rejected"
                if record.status == "REJECTED"
                else "approved"
            )
            if record.approval.status.value != expected_status:
                raise ValueError("RESTRICTED_APPROVAL_STATE_REJECTED")
            old = records.get(record.candidate_id)
            if old is None:
                if record.status != "PENDING_APPROVAL":
                    raise ValueError("RESTRICTED_INITIAL_STATE_REJECTED")
            elif (
                old.action != record.action
                or record.status not in allowed.get(old.status, set())
                or old.approval.model_dump(exclude={"status", "decision"})
                != record.approval.model_dump(exclude={"status", "decision"})
                or (old.status != "PENDING_APPROVAL" and old.approval != record.approval)
            ):
                raise ValueError("RESTRICTED_HISTORY_REJECTED")
            records[record.candidate_id] = record
        return records

    def _records(self, c):
        return self.read_records(self._events(c))

    def _load(self, c, identity):
        record = self._records(c).get(identity)
        if record is None:
            raise ValueError("RESTRICTED_REQUEST_NOT_FOUND")
        return record

    def _save(self, c, record):
        record = RestrictedRecord.model_validate_json(record.model_dump_json())
        self.store._audit(c, "RESTRICTED_RECORD", {"record": record.model_dump(mode="json")})

    def records(self) -> tuple[RestrictedRecord, ...]:
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            return tuple(self._records(c).values())

    def settings(self) -> dict[str, str | bool]:
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            enabled = any(e["kind"] == "RESTRICTED_TEST_MODE" for e in self._events(c))
            health = "DISABLED"
            if enabled:
                try:
                    registration = self._mode(c)
                    observed = self.resource.probe(registration)
                    health = (
                        "UNKNOWN"
                        if any(
                            r.status in ("STARTED", "UNKNOWN") for r in self._records(c).values()
                        )
                        else "VALIDATED_TEST_RESOURCE"
                        if observed == self._expected_resource_digest(c)
                        else "BLOCKED"
                    )
                except (ValueError, OSError, ExecutionDeniedError):
                    health = "BLOCKED"
        return {
            "response_mode": "TEST_RESOURCE_QUARANTINE" if enabled else "DISABLED",
            "restricted_executor_enabled": enabled,
            "resource_health": health,
            "automatic_approval": False,
            "os_security_execution": "DISABLED",
        }

    def _expected_resource_digest(self, c) -> str:
        completed = [
            RestrictedRecord.model_validate(e["details"]["record"])
            for e in self._events(c)
            if e["kind"] == "RESTRICTED_RECORD"
            and e["details"]["record"]["status"] in ("TEST_RESOURCE_CHANGED", "ROLLED_BACK")
        ]
        return completed[-1].receipt.output.after_digest if completed else digest(AVAILABLE)

    def _verify(self, c, record, *, resource_digest=None):
        self._runtime()
        registration = self._mode(c)
        if any(
            r.status in ("STARTED", "UNKNOWN") and r.candidate_id != record.candidate_id
            for r in self._records(c).values()
        ):
            raise ExecutionDeniedError("RESTRICTED_RESOURCE_OUTCOME_UNKNOWN")
        value = RestrictedInput.model_validate(record.action.input_payload())
        finding, investigation, evidence = self.monitor.simulation._context(c, value.finding_id)
        if (
            (
                finding.digest,
                investigation,
                evidence,
                finding.incident_id,
                finding.evidence_references,
            )
            != (
                value.finding_digest,
                value.investigation_digest,
                value.evidence_digest,
                value.incident_id,
                value.evidence_references,
            )
            or registration.digest != value.resource_registration_digest
            or self._policy_digest() != value.policy_digest
            or self.monitor.config.digest != value.runtime_config_digest
            or self.store.config.digest != value.runtime_config_digest
            or self.resource.probe(registration) != (resource_digest or value.before_digest)
        ):
            raise ExecutionDeniedError("RESTRICTED_CONTEXT_OR_RESOURCE_CHANGED")
        if value.original_receipt_digest is not None:
            originals = [
                r
                for r in self._records(c).values()
                if r.receipt and r.receipt.digest == value.original_receipt_digest
            ]
            if len(originals) != 1 or originals[0].status != "TEST_RESOURCE_CHANGED":
                raise ExecutionDeniedError("RESTRICTED_ROLLBACK_ORIGINAL_REJECTED")
            original = originals[0]
            previous = RestrictedInput.model_validate(original.action.input_payload())
            if (
                previous.action_type != "TEST_RESOURCE_QUARANTINE"
                or previous.finding_id != value.finding_id
                or original.receipt.output.after_digest != value.before_digest
                or original.receipt.output.before_digest != digest(AVAILABLE)
            ):
                raise ExecutionDeniedError("RESTRICTED_ROLLBACK_BINDING_REJECTED")
        return registration, value

    def _executor(self, action, approval=None, sock=None):
        registry = ToolRegistry()
        guard = RestrictedDispatchGuard(action)
        registry.execution_guard = guard

        async def change(value: RestrictedInput):
            def revalidate() -> ResourceRegistration:
                uid = authenticated_uid(sock)
                with self.store.database.transaction(write=False) as c:
                    record = self._load(c, content_digest_payload(value.model_dump(mode="json")))
                    if record.status != "STARTED" or record.action != action:
                        raise ExecutionDeniedError("RESTRICTED_RESERVATION_REQUIRED")
                    executor.preflight(record.action, approval_id=record.approval.approval_id)
                    if record.approval.decision.decided_by != f"os-uid:{uid}":
                        raise ExecutionDeniedError("RESTRICTED_OPERATOR_BINDING_REJECTED")
                    return self._verify(c, record)[0]

            registration = revalidate()
            after = QUARANTINED if value.action_type == "TEST_RESOURCE_QUARANTINE" else AVAILABLE

            def authorize_write() -> None:
                revalidate()

            return self.resource.change(
                registration, value.before_digest, after, before_write=authorize_write
            )

        registry.register(Tool(METADATA, RestrictedInput, MarkerOutput, change))
        approvals = ApprovalManager(clock=self.clock)
        if approval is not None:
            approvals.restore(approval)
        executor = GovernedExecutor(registry=registry, policy=self.policy, approvals=approvals)
        return executor, approvals, guard

    def request(
        self,
        finding_id: str,
        *,
        sock: PeerSocket,
        original_candidate: str | None = None,
        ttl_seconds: int = 300,
    ) -> RestrictedRecord:
        authenticated_uid(sock)
        self._runtime()
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86400:
            raise ValueError("RESTRICTED_TTL_REJECTED")
        self.store.verify_audit()
        with self.store.database.transaction() as c:
            registration = self._mode(c)
            if any(r.status in ("STARTED", "UNKNOWN") for r in self._records(c).values()):
                raise ExecutionDeniedError("RESTRICTED_RESOURCE_OUTCOME_UNKNOWN")
            finding, investigation, evidence = self.monitor.simulation._context(c, finding_id)
            original_digest = None
            action_type = "TEST_RESOURCE_QUARANTINE"
            before = digest(AVAILABLE)
            if original_candidate is not None:
                original = self._load(c, original_candidate)
                if (
                    original.status != "TEST_RESOURCE_CHANGED"
                    or original.action.incident_id != finding.incident_id
                ):
                    raise ValueError("RESTRICTED_ROLLBACK_ORIGINAL_REJECTED")
                if (
                    RestrictedInput.model_validate(original.action.input_payload()).finding_id
                    != finding_id
                ):
                    raise ValueError("RESTRICTED_ROLLBACK_FINDING_REJECTED")
                original_digest = original.receipt.digest
                action_type, before = "TEST_RESOURCE_ROLLBACK", original.receipt.output.after_digest
            value = RestrictedInput(
                action_type=action_type,
                resource_registration_digest=registration.digest,
                finding_id=finding_id,
                finding_digest=finding.digest,
                incident_id=finding.incident_id,
                investigation_digest=investigation,
                evidence_digest=evidence,
                evidence_references=finding.evidence_references,
                policy_digest=self._policy_digest(),
                runtime_config_digest=self.monitor.config.digest,
                before_digest=before,
                original_receipt_digest=original_digest,
            )
            identity = content_digest_payload(value.model_dump(mode="json"))
            existing = self._records(c).get(identity)
            if existing:
                return existing
            action = ActionProposal(
                action_id=uuid5(NAMESPACE_URL, identity),
                incident_id=finding.incident_id,
                tool_name=NAME,
                tool_input=value.model_dump(mode="json"),
                created_at=self.clock(),
            )
            executor, _, _ = self._executor(action)
            approval = executor.request_approval(
                action,
                reason="TEST marker only; explicit OS-peer human review",
                expires_at=self.clock() + timedelta(seconds=ttl_seconds),
            )
            record = RestrictedRecord(candidate_id=identity, action=action, approval=approval)
            self._verify(c, record)
            self._save(c, record)
            return record

    def review(
        self,
        identity: str,
        *,
        approve: bool,
        sock: PeerSocket,
        expected_digest: str,
    ) -> RestrictedRecord:
        uid = authenticated_uid(sock)
        if type(approve) is not bool:
            raise ValueError("RESTRICTED_REVIEW_REJECTED")
        self.store.verify_audit()
        with self.store.database.transaction() as c:
            record = self._load(c, identity)
            if record.digest != expected_digest or record.status != "PENDING_APPROVAL":
                raise ExecutionDeniedError("RESTRICTED_REVIEW_SNAPSHOT_CHANGED")
            self._verify(c, record)
            _, approvals, _ = self._executor(record.action, record.approval)
            decision = approvals.approve if approve else approvals.reject
            approval = decision(record.approval.approval_id, actor=f"os-uid:{uid}")
            updated = record.model_copy(
                update={"approval": approval, "status": "APPROVED" if approve else "REJECTED"}
            )
            self._save(c, updated)
            return updated

    async def execute(
        self,
        identity: str,
        *,
        sock: PeerSocket,
        expected_digest: str,
    ) -> RestrictedRecord:
        uid = authenticated_uid(sock)
        self.store.verify_audit()
        with self.store.database.transaction() as c:
            record = self._load(c, identity)
            if record.digest != expected_digest or record.status not in (
                "PENDING_APPROVAL",
                "APPROVED",
                "REJECTED",
            ):
                raise ExecutionDeniedError("RESTRICTED_ALREADY_ATTEMPTED_OR_CHANGED")
            self._verify(c, record)
            executor, _, _ = self._executor(record.action, record.approval, sock)
            executor.preflight(record.action, approval_id=record.approval.approval_id)
            started = record.model_copy(update={"status": "STARTED"})
            self._save(c, started)  # Durable reservation + audit precede any file modification.
        try:
            result = await executor.execute(record.action, approval_id=record.approval.approval_id)
            with self.store.database.transaction() as c:
                current = self._load(c, identity)
                if current != started:
                    raise ValueError("RESTRICTED_COMPLETION_RACE")
                self._verify(c, current, resource_digest=result.output.after_digest)
                receipt = RestrictedReceipt(
                    action_id=record.action.action_id,
                    approval_id=record.approval.approval_id,
                    input_digest=record.candidate_id,
                    output=result.output,
                    operator_uid=uid,
                    recorded_at=self.clock(),
                )
                value = RestrictedInput.model_validate(record.action.input_payload())
                done = started.model_copy(
                    update={
                        "status": "TEST_RESOURCE_CHANGED"
                        if value.action_type == "TEST_RESOURCE_QUARANTINE"
                        else "ROLLED_BACK",
                        "receipt": receipt,
                    }
                )
                self._save(c, done)  # Receipt and its audit are the SAME transaction.
            return done
        except (ExecutionError, ToolError, ValueError, OSError, StorageError):
            self.recover()
            raise

    def recover(self) -> None:
        self.store.verify_audit()
        with self.store.database.transaction() as c:
            for record in self._records(c).values():
                if record.status != "STARTED":
                    continue
                observed, observation = None, "UNAVAILABLE"
                try:
                    observed = self.resource.probe(self._mode(c))
                    value = RestrictedInput.model_validate(record.action.input_payload())
                    after = (
                        QUARANTINED
                        if value.action_type == "TEST_RESOURCE_QUARANTINE"
                        else AVAILABLE
                    )
                    observation = (
                        "UNCHANGED"
                        if observed == value.before_digest
                        else "EXPECTED_AFTER"
                        if observed == digest(after)
                        else "CONFLICT"
                    )
                except (ValueError, OSError, ExecutionDeniedError):
                    pass  # Explicit UNAVAILABLE, never a successful effect or automatic replay.
                self._save(
                    c,
                    record.model_copy(
                        update={
                            "status": "UNKNOWN",
                            "observed_digest": observed,
                            "recovery_observation": observation,
                        }
                    ),
                )
            records = self._records(c)
            configured = any(e["kind"] == "RESTRICTED_TEST_MODE" for e in self._events(c))
            if not configured or any(r.status == "UNKNOWN" for r in records.values()):
                return
            expected = self._expected_resource_digest(c)
            try:
                actual = self.resource.probe(self._mode(c))
                if actual != expected:
                    raise ValueError("RESTRICTED_RECOVERY_STATE_CONFLICT")
            except (ValueError, OSError, ExecutionDeniedError):
                if not any(e["kind"] == "RESTRICTED_RECOVERY_CONFLICT" for e in self._events(c)):
                    self.store._audit(
                        c,
                        "RESTRICTED_RECOVERY_CONFLICT",
                        {
                            "status": "BLOCKED",
                            "expected_digest": expected,
                            "automatic_repair": False,
                        },
                    )


def read_restricted_status(
    store: "RuntimeStore", simulation: "RuntimeResponseSimulation"
) -> dict[str, str | int]:
    """Read-only response ledger health; never reconcile or retry uncertain effects."""
    store.verify_audit()
    with store.database.transaction(write=False) as connection:
        events = simulation._events(connection)
        records = RestrictedResponseExecutor.read_records(events)
    unknown = sum(r.status == "UNKNOWN" for r in records.values())
    started = sum(r.status == "STARTED" for r in records.values())
    conflict = any(e["kind"] == "RESTRICTED_RECOVERY_CONFLICT" for e in events)
    configured = any(e["kind"] == "RESTRICTED_TEST_MODE" for e in events)
    return {
        "state": "BLOCKED"
        if conflict
        else "UNKNOWN"
        if unknown or started
        else "CLEAR"
        if configured
        else "DISABLED",
        "unknown": unknown,
        "started": started,
    }
