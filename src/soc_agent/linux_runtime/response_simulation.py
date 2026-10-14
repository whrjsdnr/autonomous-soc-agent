"""Opt-in test-identity review of immutable runtime lineage; only a pure demo handler.

No real adapter, auto approval, remote API, shell execution or operating DB migration.
The existing monitor audit is the durable record: no parallel Incident/Approval engine.
"""

import json
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Literal, Self
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, model_validator

from soc_agent.approval import ApprovalManager, ApprovalRequest
from soc_agent.approval.errors import ApprovalError
from soc_agent.assessment import AssessmentResult
from soc_agent.demo.tools import DemoIdentityOutput, demo_response_tool
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.binding import validate_binding
from soc_agent.execution.errors import ExecutionDeniedError, ExecutionError
from soc_agent.investigation import InvestigationResult
from soc_agent.linux_runtime.findings import validate_finding
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.policy import PolicyDecision, PolicyEngine
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import (
    AuthenticationReadView,
    read_authentication_view,
)
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.state.evidence import utc_now
from soc_agent.tools import ToolRegistry


class SimulationRequest(Snapshot):
    contract_version: Literal["soc-runtime-response-simulation:v1"] = (
        "soc-runtime-response-simulation:v1"
    )
    candidate_id: Hash
    finding_id: Hash
    finding_digest: Hash
    investigation_result_digest: Hash
    evidence_digest: Hash
    action: ActionProposal
    mode: Literal["RESPONSE_SIMULATION"] = "RESPONSE_SIMULATION"
    actual_response_execution: Literal["DISABLED"] = "DISABLED"
    automatic_human_approval: Literal["DISABLED"] = "DISABLED"

    @model_validator(mode="after")
    def identity(self) -> Self:
        expected = content_digest_payload(
            {"finding": self.finding_id, "result": self.investigation_result_digest}
        )
        if self.candidate_id != expected or self.action.action_id != uuid5(NAMESPACE_URL, expected):
            raise ValueError("SIMULATION_ACTION_IDENTITY_REJECTED")
        if self.action.tool_name != "disable_demo_account":
            raise ValueError("SIMULATION_ONLY_TOOL_REQUIRED")
        return self


class SimulationRecord(Snapshot):
    request: SimulationRequest
    approval: ApprovalRequest
    status: Literal[
        "PENDING_REVIEW", "APPROVED", "REJECTED", "STARTED", "SIMULATED", "UNCERTAIN", "DENIED"
    ]
    actor_assurance: Literal["NO_DECISION", "EXPLICIT_TEST_IDENTITY"] = "NO_DECISION"
    output: DemoIdentityOutput | None = None
    simulated_handler_calls: int | None = Field(default=0, ge=0, le=1)
    real_os_handler_calls: Literal[0] = 0

    @model_validator(mode="after")
    def binding(self) -> Self:
        validate_binding(self.request.action, self.approval, demo_response_tool().metadata)
        if self.status == "PENDING_REVIEW" and self.approval.status.value != "pending":
            raise ValueError("SIMULATION_REVIEW_STATE_REJECTED")
        if self.status == "REJECTED" and self.approval.status.value != "rejected":
            raise ValueError("SIMULATION_REJECTION_STATE_REJECTED")
        if (
            self.status in ("APPROVED", "STARTED", "SIMULATED", "UNCERTAIN", "DENIED")
            and self.approval.status.value != "approved"
        ):
            raise ValueError("SIMULATION_APPROVAL_STATE_REJECTED")
        if (self.status == "SIMULATED") != (self.output is not None):
            raise ValueError("SIMULATION_RESULT_MISSING_OR_UNEXPECTED")
        if self.status == "SIMULATED" and self.simulated_handler_calls != 1:
            raise ValueError("SIMULATION_CALL_COUNT_REJECTED")
        if self.status in ("STARTED", "UNCERTAIN") and self.simulated_handler_calls is not None:
            raise ValueError("SIMULATION_UNCERTAIN_COUNT_MUST_BE_UNKNOWN")
        if (
            self.output is not None
            and self.output.account_id != self.request.action.input_payload()["account_id"]
        ):
            raise ValueError("SIMULATION_OUTPUT_BINDING_REJECTED")
        if self.approval.decision is not None and (
            self.actor_assurance != "EXPLICIT_TEST_IDENTITY"
            or re.fullmatch(r"test:[A-Za-z0-9_-]{1,48}", self.approval.decision.decided_by) is None
        ):
            raise ValueError("SIMULATION_TEST_ACTOR_ASSURANCE_REJECTED")
        return self


class RuntimeResponseSimulation:
    """Caller owns the lifetime runtime writer lock; SQLite serializes duplicate reservations.

    Review identities are explicit local test identities, not production authentication.
    The response registry is private composition containing only a pure simulation tool;
    investigation's read-only registry/capability is never reused or upgraded.
    """

    def __init__(
        self,
        store: RuntimeStore,
        pipeline: AuthenticationPipeline,
        *,
        clock: Callable[[], datetime] = utc_now,
        policy: PolicyEngine | None = None,
    ):
        if store.config.incident_id != pipeline.incident_id:
            raise ValueError("SIMULATION_RUNTIME_INCIDENT_MISMATCH")
        self.store, self.pipeline, self.clock = store, pipeline, clock
        self.policy = policy or PolicyEngine()

    def _events(self, c):
        return [
            json.loads(row[0])
            for row in c.execute("SELECT payload FROM monitor_audit ORDER BY sequence")
        ]

    def _enabled(self, c):
        values = [
            e["details"]["enabled"] for e in self._events(c) if e["kind"] == "SIMULATION_MODE_SET"
        ]
        if any(type(v) is not bool for v in values):
            raise ValueError("SIMULATION_MODE_INTEGRITY_REJECTED")
        return values[-1] if values else False

    def enabled(self):
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            return self._enabled(c)

    def set_enabled(self, enabled: bool):
        if type(enabled) is not bool:
            raise ValueError("SIMULATION_OPT_IN_REJECTED")
        self.store.event(
            "SIMULATION_MODE_SET",
            {
                "enabled": enabled,
                "actual_response_execution": "DISABLED",
                "automatic_human_approval": "DISABLED",
            },
        )

    def _load(self, c, identity: str) -> SimulationRecord:
        records = [
            SimulationRecord.model_validate(e["details"]["record"])
            for e in self._events(c)
            if e["kind"] == "SIMULATION_RECORD"
            and e["details"]["record"]["request"]["candidate_id"] == identity
        ]
        if not records:
            raise ValueError("SIMULATION_REQUEST_NOT_FOUND")
        if records[0].status != "PENDING_REVIEW":
            raise ValueError("SIMULATION_INITIAL_STATE_REJECTED")
        allowed = {
            "PENDING_REVIEW": {"APPROVED", "REJECTED"},
            "APPROVED": {"STARTED"},
            "STARTED": {"SIMULATED", "UNCERTAIN", "DENIED"},
        }
        for old, new in zip(records, records[1:], strict=False):
            if old.request != new.request or new.status not in allowed.get(old.status, set()):
                raise ValueError("SIMULATION_HISTORY_REJECTED")
            if old.approval.model_dump(exclude={"status", "decision"}) != new.approval.model_dump(
                exclude={"status", "decision"}
            ):
                raise ValueError("SIMULATION_APPROVAL_BINDING_REJECTED")
            if old.status != "PENDING_REVIEW" and old.approval != new.approval:
                raise ValueError("SIMULATION_DECISION_REPLAY_REJECTED")
        return records[-1]

    def load(self, identity):
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            return self._load(c, identity)

    def records(self):
        self.store.verify_audit()
        with self.store.database.transaction(write=False) as c:
            identities = {
                e["details"]["record"]["request"]["candidate_id"]
                for e in self._events(c)
                if e["kind"] == "SIMULATION_RECORD"
            }
            return tuple(self._load(c, i) for i in sorted(identities))

    def _save(self, c, record):
        record = SimulationRecord.model_validate_json(record.model_dump_json())
        self.store._audit(c, "SIMULATION_RECORD", {"record": record.model_dump(mode="json")})

    def _context(self, c, finding_id):
        row = c.execute("SELECT * FROM monitor_findings WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            raise ValueError("SIMULATION_FINDING_MISSING")
        finding = self.store._decode(row)
        if row["status"] not in ("DONE", "DONE_SCRIPTED", "DONE_READ_ONLY"):
            raise ValueError("SIMULATION_REQUIRES_COMPLETED_INVESTIGATION")
        result = json.loads(row["result"])
        if result.get("write_disposition") != "WRITE_DENIED" or "investigation" not in result:
            raise ValueError("SIMULATION_INVESTIGATION_RECEIPT_REJECTED")
        investigation = InvestigationResult.model_validate(result["investigation"])
        if (
            investigation.incident_state.incident_id != finding.incident_id
            or investigation.plan.incident_id != finding.incident_id
            or any(
                step.status.value != "completed" or step.tool_name != "read_authentication_context"
                for step in investigation.plan.steps
            )
            or result.get("investigation_digest") != content_digest_payload(result["investigation"])
        ):
            raise ValueError("SIMULATION_INVESTIGATION_BINDING_REJECTED")
        if "assessment" in result:
            assessment = AssessmentResult.model_validate(result["assessment"])
            if (
                assessment.incident_state.incident_id != finding.incident_id
                or assessment.threat_assessment.incident_id != finding.incident_id
                or result.get("assessment_digest") != content_digest_payload(result["assessment"])
            ):
                raise ValueError("SIMULATION_ASSESSMENT_BINDING_REJECTED")
        validate_finding(self.pipeline, finding)
        view = read_authentication_view(self.pipeline)
        linked = [
            w.model_dump(mode="json")
            for w in view.authentication_window
            if set(w.source_reference) & set(finding.evidence_references)
        ]
        if not linked:
            raise ValueError("SIMULATION_WINDOW_MISSING")
        # Use windows actually returned by completed READ steps; do not attach
        # newly arrived evidence to an old investigation without another review.
        read_windows = []
        by_id = {e.evidence_id: e for e in investigation.incident_state.evidence}
        for step in investigation.plan.steps:
            evidence = by_id.get(step.evidence_id)
            if (
                evidence is None
                or evidence.tool_name != step.tool_name
                or not isinstance(evidence.raw_data, str)
            ):
                raise ValueError("SIMULATION_READ_EVIDENCE_MISSING")
            try:
                read = AuthenticationReadView.model_validate(
                    json.loads(evidence.raw_data)["output"]
                )
            except (ValueError, KeyError, TypeError) as error:
                raise ValueError("SIMULATION_READ_EVIDENCE_REJECTED") from error
            if read.incident_id != finding.incident_id:
                raise ValueError("SIMULATION_READ_INCIDENT_MISMATCH")
            read_windows.extend(w.model_dump(mode="json") for w in read.authentication_window)
        if any(window not in read_windows for window in linked):
            raise ValueError("SIMULATION_EVIDENCE_OR_INCIDENT_CHANGED")
        evidence = content_digest_payload(
            {
                "finding": finding.digest,
                "sources": list(finding.evidence_references),
                "windows": linked,
                "provenance": list(finding.provenance),
            }
        )
        return finding, row["result_digest"], evidence

    def _verify(self, c, record):
        finding, result, evidence = self._context(c, record.request.finding_id)
        request = record.request
        if (finding.digest, result, evidence, finding.incident_id) != (
            request.finding_digest,
            request.investigation_result_digest,
            request.evidence_digest,
            request.action.incident_id,
        ):
            raise ValueError("SIMULATION_EVIDENCE_OR_INCIDENT_CHANGED")

    def _executor(self, approval=None):
        registry = ToolRegistry()
        registry.register(demo_response_tool())  # Fixed pure handler. No injected OS adapters.
        approvals = ApprovalManager(clock=self.clock)
        if approval is not None:
            approvals.restore(approval)
        if (
            self.policy.evaluate(registry.get("disable_demo_account").metadata).decision
            != PolicyDecision.REQUIRE_APPROVAL
        ):
            raise ExecutionDeniedError("Simulation requires current approval policy")
        return GovernedExecutor(
            registry=registry, policy=self.policy, approvals=approvals
        ), approvals

    def request(self, finding_id: str, *, ttl_seconds: int = 300) -> SimulationRecord:
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86400:
            raise ValueError("SIMULATION_APPROVAL_TTL_REJECTED")
        self.store.verify_audit()
        with self.store.database.transaction() as c:
            if not self._enabled(c):
                raise ValueError("RESPONSE_SIMULATION_DISABLED")
            finding, result_digest, evidence = self._context(c, finding_id)
            identity = content_digest_payload({"finding": finding_id, "result": result_digest})
            if any(
                e["kind"] == "SIMULATION_RECORD"
                and e["details"]["record"]["request"]["candidate_id"] == identity
                for e in self._events(c)
            ):
                existing = self._load(c, identity)
                self._verify(c, existing)
                return existing
            executor, _ = self._executor()
            action = ActionProposal(
                action_id=uuid5(NAMESPACE_URL, identity),
                incident_id=finding.incident_id,
                tool_name="disable_demo_account",
                tool_input={"account_id": "demo-alice"},
                created_at=self.clock(),
            )
            approval = executor.request_approval(
                action,
                reason="Simulation only; test identity review required",
                expires_at=self.clock() + timedelta(seconds=ttl_seconds),
            )
            record = SimulationRecord(
                request=SimulationRequest(
                    candidate_id=identity,
                    finding_id=finding_id,
                    finding_digest=finding.digest,
                    investigation_result_digest=result_digest,
                    evidence_digest=evidence,
                    action=action,
                ),
                approval=approval,
                status="PENDING_REVIEW",
            )
            self._save(c, record)
            return record

    def prepare_completed(self):
        if not self.enabled():
            return
        with self.store.database.transaction(write=False) as c:
            identities = [
                r[0]
                for r in c.execute(
                    "SELECT id FROM monitor_findings WHERE status IN "
                    "('DONE','DONE_SCRIPTED','DONE_READ_ONLY')"
                )
            ]
        requested = {r.request.finding_id for r in self.records()}
        for identity in identities:
            if identity not in requested:
                self.request(identity)

    def review(self, identity: str, *, approve: bool, test_reviewer: str):
        try:
            return self._review(identity, approve=approve, test_reviewer=test_reviewer)
        except (ValueError, ApprovalError) as error:
            self.store.event(
                "SIMULATION_REVIEW_DENIED",
                {
                    "candidate_reference": content_digest_payload({"candidate": identity})
                    if isinstance(identity, str)
                    else None,
                    "category": type(error).__name__,
                },
            )
            raise

    def _review(self, identity: str, *, approve: bool, test_reviewer: str):
        if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise ValueError("SIMULATION_CANDIDATE_ID_REJECTED")
        if type(approve) is not bool:
            raise ValueError("SIMULATION_REVIEW_DECISION_REJECTED")
        if not isinstance(test_reviewer, str) or not re.fullmatch(
            r"test:[A-Za-z0-9_-]{1,48}", test_reviewer
        ):
            raise ValueError("EXPLICIT_TEST_REVIEWER_REQUIRED")
        self.store.verify_audit()
        with self.store.database.transaction() as c:
            if not self._enabled(c):
                raise ValueError("RESPONSE_SIMULATION_DISABLED")
            record = self._load(c, identity)
            self._verify(c, record)
            if record.status != "PENDING_REVIEW":
                raise ValueError("SIMULATION_ALREADY_DECIDED")
            _, approvals = self._executor(record.approval)
            decision = approvals.approve if approve else approvals.reject
            approval = decision(record.approval.approval_id, actor=test_reviewer)
            updated = record.model_copy(
                update={
                    "approval": approval,
                    "status": "APPROVED" if approve else "REJECTED",
                    "actor_assurance": "EXPLICIT_TEST_IDENTITY",
                }
            )
            self._save(c, updated)
            return updated

    async def execute(self, identity: str, *, action: ActionProposal | None = None):
        self.store.verify_audit()
        try:
            if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
                raise ValueError("SIMULATION_CANDIDATE_ID_REJECTED")
            with self.store.database.transaction() as c:
                if not self._enabled(c):
                    raise ValueError("RESPONSE_SIMULATION_DISABLED")
                record = self._load(c, identity)
                self._verify(c, record)
                if record.status not in ("PENDING_REVIEW", "APPROVED", "REJECTED"):
                    raise ValueError("SIMULATION_ALREADY_ATTEMPTED")
                executor, _ = self._executor(record.approval)
                selected = action or record.request.action
                if selected != record.request.action:
                    raise ExecutionDeniedError("Simulation target/incident binding changed")
                executor.preflight(selected, approval_id=record.approval.approval_id)
                if record.status != "APPROVED":
                    raise ExecutionDeniedError("Explicit simulation approval required")
                started = record.model_copy(
                    update={"status": "STARTED", "simulated_handler_calls": None}
                )
                self._save(c, started)  # Commit reservation AND audit before invoking pure handler.
            output = await executor.execute(selected, approval_id=record.approval.approval_id)
            with self.store.database.transaction() as c:
                current = self._load(c, identity)
                self._verify(c, current)
                if current != started:
                    raise ValueError("SIMULATION_COMPLETION_RACE")
                done = started.model_copy(
                    update={
                        "status": "SIMULATED",
                        "output": output.output,
                        "simulated_handler_calls": 1,
                    }
                )
                self._save(c, done)
            return done
        except (ValueError, RuntimeError, ExecutionError) as error:
            self.store.event(
                "SIMULATION_DENIED",
                {
                    "candidate_reference": content_digest_payload({"candidate": identity})
                    if isinstance(identity, str)
                    else None,
                    "category": type(error).__name__,
                    "real_os_handler_calls": 0,
                },
            )
            raise

    def recover(self):
        # Never replay a reserved attempt: result could have been lost after the pure return.
        self.store.verify_audit()
        with self.store.database.transaction() as c:
            identities = {
                e["details"]["record"]["request"]["candidate_id"]
                for e in self._events(c)
                if e["kind"] == "SIMULATION_RECORD"
            }
            records = [self._load(c, identity) for identity in identities]
            for record in records:
                if record.status == "STARTED":
                    self._save(c, record.model_copy(update={"status": "UNCERTAIN"}))
