"""Deterministic broker transactions over an in-memory TC registry only."""

import time
from collections.abc import Callable

from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan, Command, Ownership
from soc_agent.security_ai.ebpf_broker.ownership import Registry
from soc_agent.security_ai.research.models import digest


class Engine:
    def __init__(self, plan: BrokerPlan, record: Callable, validate: Callable):
        self.plan, self.record, self.validate = plan, record, validate
        self.registry = Registry()
        self.owner: Ownership | None = None
        self.sequence, self.run_count = 0, 0
        self.seen_sessions, self.seen_generations = set(), set()
        self.state, self.cleanup = "NOT_PREPARED", "NOT_OBSERVED"
        self.last_error: str | None = None
        self.born = self.last_heartbeat = time.monotonic()
        self.run_started: float | None = None
        self.exited = False

    def cleanup_owned(self, reason: str) -> None:
        self.record("STOP_REQUESTED", reason=reason)
        prior = self.last_error
        self.state = "STOPPING"
        try:
            if self.owner:
                self.registry.detach(self.owner, self.record)
                self.owner = None
            self.record("CLEANUP_VERIFIED", scope="FIXTURE_REGISTRY_ONLY", reason=reason)
        except (ValueError, OSError):
            self.state, self.cleanup, self.last_error = (
                "ERROR",
                "ORPHANED_OR_CLEANUP_UNVERIFIED",
                "BROKER_CLEANUP_UNVERIFIED",
            )
            self.record("CLEANUP_UNVERIFIED", code=self.last_error, user_review_required=True)
            raise ValueError(self.last_error) from None
        self.run_started = None
        self.cleanup = "FIXTURE_VERIFIED"
        self.state = "ERROR" if prior else "CLOSED"

    def tick(self, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        if current < self.last_heartbeat:
            raise ValueError("BROKER_MONOTONIC_INVALID")
        self.validate()
        if current - self.born >= self.plan.application.scope.application_deadline_seconds:
            raise ValueError("BROKER_APPLICATION_DEADLINE")
        if current - self.last_heartbeat >= self.plan.heartbeat_seconds:
            raise ValueError("BROKER_HEARTBEAT_TIMEOUT")
        if self.run_started is not None and (
            current - self.run_started >= self.plan.application.scope.max_duration_seconds
        ):
            self.cleanup_owned("TIMEOUT")

    def execute(self, command: Command) -> dict:
        try:
            return self._execute(command)
        except (ValueError, OSError):
            if self.registry.pending_owner is not None:
                self.owner = self.registry.pending_owner
            self.fail("BROKER_COMMAND_TRANSACTION_FAILED")
            raise

    def _execute(self, command: Command) -> dict:
        if self.exited or command.sequence != self.sequence + 1:
            raise ValueError("BROKER_COMMAND_REPLAY_OR_SEQUENCE")
        if command.plan_digest != self.plan.identity:
            raise ValueError("BROKER_SESSION_DIGEST_MISMATCH")
        self.tick()
        self.sequence = command.sequence
        self.last_heartbeat = time.monotonic()
        if self.last_error and command.command not in {"STATUS", "STOP", "CLEANUP"}:
            raise ValueError("BROKER_FAILED_NO_RETRY")
        if command.command == "PREPARE":
            if self.state != "NOT_PREPARED":
                raise ValueError("BROKER_PREPARATION_REUSE")
            self.state = "BROKER_READY"
            self.record("BROKER_READY", scope="UNPRIVILEGED_FIXTURE", native_authentication=False)
        elif command.command == "ATTACH":
            if self.state not in {"BROKER_READY", "CLOSED"} or self.owner:
                raise ValueError("BROKER_ATTACH_STATE_DENIED")
            run = command.run
            scope = self.plan.application.scope
            if (
                run.application_session != self.plan.application.application_session
                or run.scope_digest != digest(scope.model_dump(mode="json"))
                or run.run_number != self.run_count + 1
                or run.run_number > scope.max_runs
                or run.capture_session in self.seen_sessions
                or run.generation in self.seen_generations
            ):
                raise ValueError("BROKER_RUN_SCOPE_OR_SEQUENCE")
            # Each request consumes its attempt; failures cannot be silently retried.
            self.run_count += 1
            self.seen_sessions.add(run.capture_session)
            self.seen_generations.add(run.generation)
            self.state = "ATTACH_PENDING"
            self.owner = self.registry.attach(self.plan, run, self.record)
            self.run_started = time.monotonic()
            self.cleanup = "FIXTURE_OWNED"
        elif command.command == "DETACH":
            if self.owner is None or command.ownership != self.owner:
                raise ValueError("BROKER_HOOK_OWNERSHIP_MISMATCH")
            self.cleanup_owned("USER_STOP")
        elif command.command == "STOP":
            self.cleanup_owned(command.reason)
        elif command.command == "CLEANUP":
            self.cleanup_owned("APPLICATION_EXIT")
            self.record("BROKER_EXITED", scope="FIXTURE_NO_NATIVE_RESOURCES")
            self.exited = True
        return self.snapshot()

    def fail(self, code: str) -> None:
        self.state, self.last_error = "ERROR", code
        self.cleanup = "ORPHANED_OR_CLEANUP_UNVERIFIED" if self.owner else "CLEANUP_UNVERIFIED"
        self.record("BROKER_ERROR", code=code, cleanup_status=self.cleanup)

    def snapshot(self) -> dict:
        return dict(
            state=self.state,
            source="PHASE_B1_FIXTURE_NOT_NATIVE",
            native_active=False,
            last_error=self.last_error,
            cleanup_status=self.cleanup,
            hook_ownership=self.owner.model_dump(mode="json") if self.owner else None,
            registry=self.registry.snapshot(),
            command_sequence=self.sequence,
            run_count=self.run_count,
            native_ai="BLOCKED",
            dns9="BLOCKED",
            operational_gate="BLOCKED",
        )
