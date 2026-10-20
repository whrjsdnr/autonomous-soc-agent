"""App-session authority composed with the Phase A verifier and a separate fixture Broker."""

import os
import time
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan, Ownership
from soc_agent.security_ai.ebpf_broker.identity import broker_sha, bundle, verify_bundle
from soc_agent.security_ai.ebpf_broker.journal import recover
from soc_agent.security_ai.ebpf_broker.process import BrokerProcess
from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import RunIdentity
from soc_agent.security_ai.research.models import digest


class Controller:
    def __init__(self, application: Application):
        self.application = application
        self.plan = BrokerPlan(
            application=application.plan,
            uid=os.getuid(),
            gid=os.getgid(),
            broker_sha256=broker_sha(),
            bundle_digest=digest(bundle()),
        )
        self.broker: BrokerProcess | None = None
        self.run: RunIdentity | None = None
        self.ownership: Ownership | None = None
        self.state, self.cleanup = "NOT_PREPARED", "NOT_OBSERVED"
        self.error: str | None = None
        self.run_count = 0
        self.ended = False

    def _event(self, kind: str, **details) -> None:
        self.application._event(
            kind,
            broker_plan_digest=self.plan.identity,
            broker_source="PHASE_B1_FIXTURE",
            **details,
        )

    def _validate(self) -> None:
        self.application._validate()
        verify_bundle(self.plan.bundle_digest)
        if not self.application._authenticated or self.ended or self.error:
            raise ValueError("BROKER_APPLICATION_AUTHORITY_DENIED")
        if time.monotonic() - self.application._grant_started >= (
            self.application.scope.application_deadline_seconds
        ):
            raise ValueError("BROKER_APPLICATION_EXPIRED")

    def prepare(self) -> dict:
        if self.state != "NOT_PREPARED":
            raise ValueError("BROKER_SESSION_REUSE_DENIED")
        verify_bundle(self.plan.bundle_digest)
        self.application.prepare()
        self._event("BROKER_SESSION_PREPARED", broker_plan=self.plan.model_dump(mode="json"))
        self.state = "APPROVAL_REQUIRED"
        return self.snapshot()

    def approve(self, expected: str) -> None:
        if expected != self.plan.identity:
            raise ValueError("BROKER_APPROVAL_DIGEST_MISMATCH")
        self.application.approve(self.application.plan.identity)
        self._event("BROKER_APPROVAL_ACCEPTED", scope="FIXTURE_ONLY_NO_NATIVE_PERMISSION")

    def authenticate(self, fixture: FixtureAuthentication) -> dict:
        if self.state != "APPROVAL_REQUIRED" or self.broker:
            raise ValueError("BROKER_AUTHENTICATION_REUSE_DENIED")
        self.state = "AUTHENTICATING"
        try:
            self.application.authenticate(fixture)
            self._validate()
            self.broker = BrokerProcess(
                self.plan, self.application.program, self.application.directory
            )
            self.broker.request("PREPARE")
            self._event(
                "BROKER_READY",
                identity=self.broker.identity.model_dump(),
                privilege="NONE",
                broker_plan_digest_verified=self.plan.identity,
            )
            self.state = "BROKER_READY"
        except (ValueError, OSError, EOFError):
            self.state, self.error = "ERROR", "BROKER_AUTHENTICATION_OR_BOOTSTRAP_FAILED"
            self.application._authenticated = False
            self.application.authentication = "FAILED"
            self._event("BROKER_START_FAILED", code=self.error)
            if self.broker:
                self.broker.close()
            raise ValueError(self.error) from None
        return self.snapshot()

    def start(self) -> dict:
        self._validate()
        if self.state not in {"BROKER_READY", "CLOSED"} or not self.broker:
            raise ValueError("BROKER_START_STATE_DENIED")
        self.run_count += 1
        self.run = RunIdentity(
            application_session=self.application.plan.application_session,
            scope_digest=digest(self.application.scope.model_dump(mode="json")),
            run_number=self.run_count,
        )
        self._event("ATTACH_REQUESTED", run=self.run.model_dump(mode="json"))
        try:
            value = self.broker.request("ATTACH", run=self.run)
        except (ValueError, OSError, EOFError):
            self._fault("BROKER_ATTACH_FAILED")
            raise ValueError("BROKER_ATTACH_FAILED") from None
        self.ownership = Ownership.model_validate(value["hook_ownership"])
        self.state, self.cleanup = "ATTACH_PENDING", value["cleanup_status"]
        self._event("ATTACH_VERIFIED", ownership=value["hook_ownership"], native_attach=False)
        return self.snapshot()

    def _fault(self, code: str) -> None:
        self.state, self.cleanup, self.error = "ERROR", "ORPHANED_OR_CLEANUP_UNVERIFIED", code
        self.application._authenticated = False
        self.application.authentication = "REVOKED"
        if self.broker:
            try:
                result = self.broker.close()
                self.cleanup = result["cleanup_status"]
                self.ownership = None
            except (ValueError, OSError, EOFError):
                self.cleanup = "ORPHANED_OR_CLEANUP_UNVERIFIED"
        self._event(
            "BROKER_ERROR",
            code=code,
            cleanup_status=self.cleanup,
            user_review_required=self.cleanup != "FIXTURE_VERIFIED",
        )

    def observe(self) -> dict:
        if not self.broker or self.ended or self.error:
            return self.snapshot()
        try:
            self._validate()
            value = self.broker.request("STATUS")
            metrics = self.broker.metrics()
            if metrics["rss_bytes"] is None or metrics["rss_bytes"] > (
                self.plan.broker_rss_mib * 1024**2
            ):
                raise ValueError("BROKER_MEMORY_BUDGET")
            self.state, self.cleanup = value["state"], value["cleanup_status"]
            self.ownership = (
                Ownership.model_validate(value["hook_ownership"])
                if value["hook_ownership"]
                else None
            )
        except (ValueError, OSError, EOFError):
            self._fault("BROKER_SUPERVISION_FAILED")
        return self.snapshot()

    def stop(self, reason="USER_STOP") -> dict:
        if self.ended:
            return self.snapshot()
        if not self.broker:
            return self.snapshot()
        self.state = "STOPPING"
        self._event("DETACH_REQUESTED", reason=reason)
        try:
            value = self.broker.request("STOP", reason=reason)
            self.ownership = None
            self.cleanup = value["cleanup_status"]
            self.state = "ERROR" if self.error else "CLOSED"
            self._event("DETACH_VERIFIED", scope="FIXTURE_OWNED_FILTER_ONLY")
        except (ValueError, OSError, EOFError):
            self._fault("BROKER_CLEANUP_UNVERIFIED")
        return self.snapshot()

    def close(self) -> dict:
        if self.ended:
            return self.snapshot()
        try:
            if self.broker:
                result = self.broker.close()
                self.cleanup = result["cleanup_status"]
                self.ownership = None
                self.state = "ERROR" if self.error else "CLOSED"
                self._event("CLEANUP_VERIFIED", scope="BROKER_FIXTURE_EXIT_AND_JOURNAL_ONLY")
                self._event("BROKER_EXITED", identity=self.broker.identity.model_dump(), code=0)
        except (ValueError, OSError, EOFError):
            self.state, self.cleanup, self.error = (
                "ERROR",
                "ORPHANED_OR_CLEANUP_UNVERIFIED",
                "BROKER_EXIT_CLEANUP_UNVERIFIED",
            )
            self._event("CLEANUP_UNVERIFIED", code=self.error, user_review_required=True)
        finally:
            self.ended = True
            self.application.close()
        return self.snapshot()

    def snapshot(self) -> dict:
        value = self.application.snapshot()
        value.update(
            state=self.state,
            last_error=self.error,
            input_origin="PHASE_B1_FIXTURE_NOT_NATIVE",
            session_id=str(self.plan.application.application_session),
        )
        detail = value["ebpf"]
        detail.update(
            collector_type="EBPF_BROKER_PHASE_B1",
            bundle_digest=self.plan.bundle_digest,
            broker_sha256=self.plan.broker_sha256,
            broker_state=self.state,
            supervisor_state=self.state,
            hook_state="FIXTURE_ATTACHED_NATIVE_PENDING" if self.ownership else "NATIVE_PENDING",
            hook_ownership=self.ownership.model_dump(mode="json") if self.ownership else None,
            cleanup_status=self.cleanup,
            authentication_state=self.application.authentication,
        )
        value["collector"].update(type="EBPF_BROKER_PHASE_B1", health=self.state)
        value["broker_plan_digest"] = self.plan.identity
        return value

    @staticmethod
    def recover(directory: Path) -> dict:
        app = Application.recover(directory)
        from soc_agent.linux_runtime.store import RuntimeStore

        store = RuntimeStore(directory)
        with store.database.transaction(write=False) as db:
            import json

            rows = [json.loads(r[0]) for r in db.execute("SELECT payload FROM monitor_audit")]
        plans = [
            r["details"]["broker_plan"] for r in rows if r["kind"] == "BROKER_SESSION_PREPARED"
        ]
        if len(plans) != 1:
            raise ValueError("BROKER_RECOVERY_PLAN_INVALID")
        plan = BrokerPlan.model_validate(plans[0])
        if str(plan.application.application_session) != app["restored_application"]:
            raise ValueError("BROKER_RECOVERY_APPLICATION_MISMATCH")
        if any(r["details"].get("broker_plan_digest") not in {None, plan.identity} for r in rows):
            raise ValueError("BROKER_RECOVERY_PLAN_MISMATCH")
        journal = recover(directory / "broker-audit.jsonl", plan.identity)
        return dict(
            **journal,
            runtime_audit_integrity=app["runtime_audit_integrity"],
            authentication="REQUIRED_NEW_APPLICATION",
            native_ai="BLOCKED",
            dns9="BLOCKED",
            operational_gate="BLOCKED",
        )
