"""One in-memory application grant; each fixture run has fresh identity/generation.

Phase A never creates privileged processes, OS authentication or Native ACTIVE capture.
"""

import json
import math
import os
import sqlite3
import time
from pathlib import Path

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import (
    ApplicationPlan,
    ProcessIdentity,
    RunIdentity,
    Scope,
    alive,
    controller_unprivileged,
)
from soc_agent.security_ai.ebpf_native.loader import (
    Inspector,
    bundle,
    capability_preflight,
    file_sha,
)
from soc_agent.security_ai.ebpf_native.tc_contract import Attachment, FixtureTC
from soc_agent.security_ai.research.models import digest


class Application:
    def __init__(self, directory: Path, plan: ApplicationPlan, program: Path, loader: Path):
        self.directory, self.plan, self.program, self.loader = directory, plan, program, loader
        self.scope = plan.scope
        self.state = "NOT_PREPARED"
        self.authentication = "REQUIRED"
        self.supervisor = "NOT_STARTED"
        self.cleanup = "NOT_OBSERVED"
        self.last_error: str | None = None
        self.store: RuntimeStore | None = None
        # These fields are never serialized, even in a checkpoint/approval file.
        self._approved_digest: str | None = None
        self._authenticated = False
        self._auth_attempted = False
        self._grant_started: float | None = None
        self._run_started: float | None = None
        self._last_clock: float | None = None
        self.inspector: Inspector | None = None
        self.run: RunIdentity | None = None
        self.loader_identity: ProcessIdentity | None = None
        self.scope_revision = 0
        self._event_count = 0
        self.run_count = 0
        self.tc = FixtureTC()
        self.attachment: Attachment | None = None

    def _event(self, kind: str, **details) -> None:
        if self.store is None:
            raise ValueError("EBPF_APP_STORE_NOT_PREPARED")
        if self._event_count >= self.scope.max_audit_events:
            self.state, self.last_error = "ERROR", "EBPF_APPLICATION_AUDIT_BUDGET"
            self._authenticated = False
            self._approved_digest = None
            self.authentication = "REVOKED"
            raise ValueError(self.last_error)
        self._event_count += 1
        try:
            self.store.event(
                kind,
                dict(
                    application_session=str(self.plan.application_session),
                    plan_digest=self.plan.identity,
                    source=self.plan.mode,
                    native_authentication=False,
                    **details,
                ),
            )
        except (OSError, ValueError, sqlite3.Error) as exc:
            self.state, self.last_error = "ERROR", "EBPF_APPLICATION_AUDIT_FAILED"
            self._authenticated = False
            self._approved_digest = None
            self.authentication = "FAILED"
            raise ValueError(self.last_error) from exc

    def _error(self, code: str) -> None:
        self.state, self.last_error = "ERROR", code
        self._authenticated = False
        self._approved_digest = None
        if self.authentication == "MOCK_VERIFIED_NOT_NATIVE":
            self.authentication = "REVOKED"
        elif self.authentication == "AUTHENTICATING":
            self.authentication = "FAILED"
        if self.store:
            self._event("PHASE_A_ERROR", code=code, cleanup=self.cleanup)
        raise ValueError(code)

    def _validate(self) -> None:
        if not alive(self.plan.controller):
            self._error("EBPF_CONTROLLER_IDENTITY_FAILED")
        if (
            os.geteuid() == 0
            or os.geteuid() != self.plan.controller.uid
            or not controller_unprivileged()
        ):
            self._error("EBPF_NON_ROOT_CONTROLLER_REQUIRED")
        try:
            namespace = os.readlink("/proc/self/ns/net")
            # sysfs belongs to the mount namespace after network-only setns.
            import socket

            index = socket.if_nametoindex("lo")
            program_sha = file_sha(self.program)
            loader_sha = file_sha(self.loader)
        except (OSError, ValueError):
            self._error("EBPF_APPLICATION_FILES_OR_ENVIRONMENT_INVALID")
        if namespace != self.scope.net_namespace:
            self._error("EBPF_NAMESPACE_MISMATCH")
        if index != self.scope.ifindex:
            self._error("EBPF_INTERFACE_IDENTITY_MISMATCH")
        if program_sha != self.scope.program_sha256:
            self._error("EBPF_PROGRAM_SHA_MISMATCH")
        if loader_sha != self.scope.loader_sha256:
            self._error("EBPF_LOADER_SHA_MISMATCH")
        if digest(bundle()) != self.scope.bundle_digest:
            self._error("EBPF_BUNDLE_MISMATCH")

    def _now(self, value: float | None) -> float:
        now = time.monotonic() if value is None else value
        if (
            not math.isfinite(now)
            or now < 0
            or (self._last_clock is not None and now < self._last_clock)
        ):
            self._error("EBPF_SUPERVISOR_CLOCK_INVALID")
        self._last_clock = now
        return now

    def prepare(self) -> dict:
        if self.state != "NOT_PREPARED":
            raise ValueError("EBPF_APP_PREPARE_REUSE_DENIED")
        self.state = "PREPARING"
        self._validate()
        create_private_directory(self.directory)
        self.store = RuntimeStore.create(
            self.directory,
            RuntimeConfig(
                incident_id=self.plan.application_session,
                repeated_failures=5,
                multiple_accounts=3,
                assessment_mode="READ_ONLY",
            ),
        )
        self._event(
            "SESSION_PREPARED",
            plan=self.plan.model_dump(mode="json"),
            capability_preflight=capability_preflight(),
        )
        # Inspector frees an unopened-to-kernel object; no program/map is loaded.
        try:
            self.inspector = Inspector(self.loader, self.scope.loader_sha256)
            result = self.inspector.inspect(self.program, self.scope.program_sha256)
        except (OSError, ValueError):
            self._error("EBPF_LOADER_PREPARATION_REJECTED")
        self._event("LOADER_INSPECTION_COMPLETED", result=result)
        self.state = "APPROVAL_REQUIRED"
        self._event("APPROVAL_REQUESTED", scope=self.scope.model_dump(mode="json"))
        return self.snapshot()

    def approve(self, approval_digest: str) -> None:
        if self.state != "APPROVAL_REQUIRED" or self._approved_digest:
            raise ValueError("EBPF_APP_APPROVAL_REUSE_DENIED")
        self._validate()
        if approval_digest != self.plan.identity:
            self._error("EBPF_APP_APPROVAL_DIGEST_MISMATCH")
        self._approved_digest = approval_digest
        self._event("APPROVAL_ACCEPTED", scope_digest=digest(self.scope.model_dump(mode="json")))

    def authenticate(self, evidence: FixtureAuthentication, *, now: float | None = None) -> dict:
        if (
            self._auth_attempted
            or self.state != "APPROVAL_REQUIRED"
            or self._approved_digest != self.plan.identity
        ):
            raise ValueError("EBPF_APP_AUTHENTICATION_ORDER_DENIED")
        self._auth_attempted = True
        self.state, self.authentication = "AUTHENTICATING", "AUTHENTICATING"
        self._event("AUTHENTICATION_STARTED", method="MOCK_OS_TERMINAL_ONLY")
        try:
            self._validate()
            evidence.verify(self.plan)
            self._validate()  # Recheck artifacts/controller/scope after authentication.
            current = self._now(now)
        except ValueError as exc:
            self.authentication = "FAILED"
            self._event("AUTHENTICATION_FAILED", code=str(exc))
            self._error(str(exc))
        self._authenticated = True
        self._grant_started = current
        self.state, self.authentication = "AUTHENTICATED", "MOCK_VERIFIED_NOT_NATIVE"
        self._event("AUTHENTICATION_VERIFIED", scope="MOCK_CONFORMANCE_NOT_PASSWORD_PROOF")
        return self.snapshot()

    def scope_approval_digest(self, scope: Scope) -> str:
        return digest(
            dict(
                application=self.plan.identity,
                scope_revision=self.scope_revision,
                previous_scope=digest(self.scope.model_dump(mode="json")),
                requested_scope=scope.model_dump(mode="json"),
            )
        )

    def approve_scope(self, scope: Scope, approval_digest: str) -> None:
        if (
            not self._authenticated
            or self.state not in {"AUTHENTICATED", "CLOSED"}
            or self.attachment is not None
        ):
            raise ValueError("EBPF_SCOPE_APPROVAL_STATE_DENIED")
        self._validate()
        if scope == self.scope:
            raise ValueError("EBPF_SCOPE_APPROVAL_NO_CHANGE")
        if self.scope_revision >= self.scope.max_scope_revisions:
            self._error("EBPF_SCOPE_REVISION_BUDGET")
        if approval_digest != self.scope_approval_digest(scope):
            raise ValueError("EBPF_SCOPE_APPROVAL_DIGEST_MISMATCH")
        self.scope = scope
        self.scope_revision += 1
        self._validate()
        self._event(
            "SCOPE_APPROVAL_ACCEPTED",
            scope=scope.model_dump(mode="json"),
            scope_revision=self.scope_revision,
        )

    def start(self, scope: Scope, *, now: float | None = None) -> dict:
        if self.state not in {"AUTHENTICATED", "CLOSED"}:
            raise ValueError("EBPF_APP_START_STATE_DENIED")
        self._validate()
        if (
            not self._authenticated
            or self._approved_digest != self.plan.identity
            or self.plan.mode != "PHASE_A_FIXTURE"
        ):
            self._error("EBPF_PHASE_A_NATIVE_EXECUTION_DISABLED")
        if scope != self.scope:
            # No authority expansion. Existing safe lease stays usable only in its old scope.
            self._event(
                "SCOPE_CHANGE_REQUIRES_APPROVAL",
                requested_scope_digest=digest(scope.model_dump(mode="json")),
            )
            raise ValueError("EBPF_SCOPE_CHANGE_REQUIRES_APPROVAL")
        if self.inspector is None:
            self._error("EBPF_LOADER_NOT_PREPARED")
        self.inspector.inspect(self.program, self.scope.program_sha256)
        current = self._now(now)
        if (
            self._grant_started is None
            or current - self._grant_started >= scope.application_deadline_seconds
        ):
            self._error("EBPF_APPLICATION_SESSION_EXPIRED")
        if self.run_count >= scope.max_runs:
            self._error("EBPF_APPLICATION_RUN_BUDGET")
        self.run_count += 1
        self.run = RunIdentity(
            application_session=self.plan.application_session,
            scope_digest=digest(scope.model_dump(mode="json")),
            run_number=self.run_count,
        )
        self.state, self.supervisor = "LOADER_READY", "FIXTURE_STARTING"
        self._event("LOADER_READY", run=self.run.model_dump(mode="json"))
        try:
            self.attachment = self.tc.attach(
                self.plan.model_copy(update={"scope": self.scope}), self.run
            )
        except ValueError:
            self._error("EBPF_TC_FIXTURE_ATTACH_FAILED")
        self.loader_identity = ProcessIdentity(
            pid=2147483647, start_ticks=self.run_count, uid=self.plan.controller.uid
        )
        self._run_started = current
        self.state, self.supervisor, self.cleanup = (
            "ATTACH_PENDING",
            "FIXTURE_RUNNING",
            "FIXTURE_PENDING",
        )
        self._event(
            "ATTACH_PENDING",
            attachment=self.attachment.model_dump(mode="json"),
            kernel_attach=False,
        )
        return self.snapshot()

    def observe(
        self,
        *,
        now: float,
        queue_depth: int = 0,
        rss_mib: float = 0,
        cpu_seconds: float = 0,
        loader_alive: bool = True,
        loader_identity: ProcessIdentity | None = None,
    ) -> dict:
        if self.state != "ATTACH_PENDING":
            raise ValueError("EBPF_SUPERVISOR_NOT_RUNNING")
        self._validate()
        current = self._now(now)
        if (
            self._grant_started is None
            or current - self._grant_started >= self.scope.application_deadline_seconds
        ):
            self.stop(reason="TIMEOUT")
            self._error("EBPF_APPLICATION_SESSION_EXPIRED")
        if not loader_alive or (
            loader_identity is not None and loader_identity != self.loader_identity
        ):
            self.supervisor = "FIXTURE_CRASHED"
            self._error("EBPF_LOADER_CRASH_FIXTURE")
        if (
            not 0 <= queue_depth <= self.scope.queue_capacity
            or not math.isfinite(rss_mib)
            or not 0 <= rss_mib <= self.scope.memory_mib
            or not math.isfinite(cpu_seconds)
            or not 0 <= cpu_seconds <= current - self._run_started
        ):
            self._error("EBPF_SUPERVISOR_RESOURCE_BOUND")
        if (
            self._run_started is None
            or current - self._run_started >= self.scope.max_duration_seconds
        ):
            return self.stop(reason="TIMEOUT")
        return self.snapshot()

    def stop(self, *, reason: str = "USER_STOP") -> dict:
        if reason not in {
            "USER_STOP",
            "GUI_CLOSE",
            "TIMEOUT",
            "CONTROLLER_EXIT",
            "APPLICATION_EXIT",
        }:
            raise ValueError("EBPF_STOP_REASON_INVALID")
        if self.state == "CLOSED" and self.attachment is None:
            return self.snapshot()
        self._event("STOP_REQUESTED", reason=reason)
        prior_error = self.last_error
        self.state = "STOPPING"
        if self.attachment:
            try:
                self.tc.detach(self.attachment)
            except ValueError:
                self.cleanup = "FIXTURE_OWNERSHIP_OR_CLEANUP_UNVERIFIED"
                self._error("EBPF_TC_CLEANUP_UNVERIFIED")
            self.attachment = None
        self.cleanup = "FIXTURE_VERIFIED_NO_KERNEL_RESOURCES_CREATED"
        self.supervisor = "FIXTURE_STOPPED"
        self.state = "ERROR" if prior_error else "CLOSED"
        self._event(
            "CLEANUP_VERIFIED", scope="FIXTURE_REGISTRY_ONLY", kernel_resources_created=False
        )
        return self.snapshot()

    def close(self) -> dict:
        try:
            if self.store:
                self.stop(reason="APPLICATION_EXIT")
        finally:
            self._authenticated = False
            self._approved_digest = None
            self._grant_started = None
            self.authentication = "REVOKED"
        return self.snapshot()

    @classmethod
    def recover(cls, directory: Path) -> dict:
        store = RuntimeStore(directory)
        audit = store.verify_audit()
        with store.database.transaction(write=False) as db:
            rows = [
                json.loads(r[0])
                for r in db.execute("SELECT payload FROM monitor_audit ORDER BY sequence")
            ]
        plans = [r["details"]["plan"] for r in rows if r["kind"] == "SESSION_PREPARED"]
        if len(plans) != 1:
            raise ValueError("EBPF_APPLICATION_RECOVERY_IDENTITY_FAILED")
        plan = ApplicationPlan.model_validate(plans[0])
        if any(
            r["details"].get("plan_digest") != plan.identity
            for r in rows
            if r["kind"] != "INITIALIZED"
        ):
            raise ValueError("EBPF_APPLICATION_RECOVERY_IDENTITY_FAILED")
        cleanup_index = max(
            (i for i, row in enumerate(rows) if row["kind"] == "CLEANUP_VERIFIED"), default=-1
        )
        attach_index = max(
            (i for i, row in enumerate(rows) if row["kind"] == "ATTACH_PENDING"), default=-1
        )
        failed = any(row["kind"] in {"PHASE_A_ERROR", "AUTHENTICATION_FAILED"} for row in rows)
        cleanup_verified = cleanup_index >= 0 and cleanup_index > attach_index
        return dict(
            state="CLOSED" if cleanup_verified and not failed else "ERROR",
            cleanup_status="FIXTURE_VERIFIED_NOT_NATIVE"
            if cleanup_verified
            else "UNVERIFIED_RECOVERY_PENDING",
            authentication="REQUIRED_NEW_APPLICATION",
            restored_application=str(plan.application_session),
            runtime_audit_integrity=audit,
            native_ai="BLOCKED",
            automatic_attach=False,
            authentication_restored=False,
            approval_restored=False,
        )

    def snapshot(self) -> dict:
        detail = dict(
            collector_type="EBPF_TC_PHASE_A",
            hook=self.scope.hook,
            interface="lo",
            program_sha256=self.scope.program_sha256,
            bundle_digest=self.scope.bundle_digest,
            loader_sha256=self.scope.loader_sha256,
            authentication_state=self.authentication,
            application_session=str(self.plan.application_session),
            hook_state="NATIVE_PENDING",
            supervisor_state=self.supervisor,
            supervisor_process_identity=self.loader_identity.model_dump()
            if self.loader_identity
            else None,
            supervisor_process_source="FIXTURE_IDENTITY_NOT_AN_OS_LOADER_PROCESS",
            cleanup_status=self.cleanup,
            native_ai="BLOCKED",
            metrics=dict(kernel_events=None, ring_loss=None, queue_depth=0),
            counter_provenance="NATIVE_HOOK_NOT_ATTACHED",
            feature_eligibility="BLOCKED_NATIVE_POLICY",
            dns_state="DNS_VISIBILITY_UNKNOWN",
            correlation="UNKNOWN",
        )
        return dict(
            state=self.state,
            last_error=self.last_error,
            session_id=str(self.plan.application_session),
            input_origin=self.plan.mode,
            collection_live=False,
            ebpf=detail,
            collector=dict(
                type="EBPF_TC_PHASE_A", health=self.supervisor, metrics=detail["metrics"]
            ),
            network=dict(state="NOT_STARTED"),
            dns=dict(state="DNS_VISIBILITY_UNKNOWN"),
            research=dict(records=[]),
            listener_ready=False,
            command_valid=False,
            native_ai="BLOCKED",
            dns9="BLOCKED",
            operational_gate="BLOCKED",
            run=self.run.model_dump(mode="json") if self.run else None,
            authentication_policy=self.plan.authentication_policy,
        )
