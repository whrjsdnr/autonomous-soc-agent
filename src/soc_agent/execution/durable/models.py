"""Durable intent and lifecycle facts; never evidence of external atomicity."""

from enum import StrEnum
from typing import Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import Field, model_validator

from soc_agent.approval import ApprovalRequest, ApprovalStatus
from soc_agent.execution.binding import validate_binding
from soc_agent.execution.models import ActionProposal
from soc_agent.policy import PolicyDecision
from soc_agent.response.advisory import ResponsePlan
from soc_agent.response.promotion.models import PromotedAction
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash, Subject, Text
from soc_agent.state.evidence import UTCTimestamp, utc_now


class Lifecycle(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


class ExecutionBinding(Frozen):
    incident_id: UUID
    promoted_action_id: Hash
    tool_name: str
    canonical_input: str
    approval_id: UUID | None


class ExecutionIntent(Frozen):
    execution_intent_id: Hash
    idempotency_key: Hash
    binding: ExecutionBinding
    plan: ResponsePlan
    promoted: PromotedAction
    approval: ApprovalRequest | None
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        target = self.promoted.content.request.target
        details = target.proposal.details
        expected = ExecutionBinding(
            incident_id=target.incident_id,
            promoted_action_id=self.promoted.promoted_id,
            tool_name=details.intent.candidate_tool,
            canonical_input=details.intent.proposed_input,
            approval_id=self.approval.approval_id if self.approval else None,
        )
        if self.binding != expected or self.execution_intent_id != content_digest(expected):
            raise ValueError("Execution intent binding/identity mismatch")
        if self.idempotency_key != self.execution_intent_id:
            raise ValueError("Idempotency identity mismatch")
        if (
            target.response_plan_id != self.plan.plan_id
            or target.proposal not in self.plan.proposed_actions
            or target.snapshot != self.plan.content.basis.snapshot
        ):
            raise ValueError("Source lineage mismatch")
        if self.approval:
            validate_binding(self.action(), self.approval, details.metadata)
            if self.approval.status != ApprovalStatus.APPROVED:
                raise ValueError("Tool Approval must be approved")
        elif self.promoted.content.current_policy.decision == PolicyDecision.REQUIRE_APPROVAL:
            raise ValueError("Tool Approval is required")
        return self

    def action(self) -> ActionProposal:
        return ActionProposal(
            action_id=uuid5(
                NAMESPACE_URL, "soc-agent:response-promotion:" + self.promoted.promoted_id
            ),
            incident_id=self.binding.incident_id,
            tool_name=self.binding.tool_name,
            tool_input=self.binding.canonical_input,
            created_at=self.promoted.created_at,
        )


class Claim(Frozen):
    token: UUID = Field(default_factory=uuid4)
    claimant: Subject
    claimed_at: UTCTimestamp
    expires_at: UTCTimestamp


class ExecutionRecord(Frozen):
    intent: ExecutionIntent
    state: Lifecycle = Lifecycle.PENDING
    revision: int = Field(default=0, ge=0, strict=True)
    claim: Claim | None = None
    invocation_started_at: UTCTimestamp | None = None
    finished_at: UTCTimestamp | None = None
    reason: Text | None = None
    result_digest: Hash | None = None
    rule_version: Literal["execution-lifecycle:v1"] = "execution-lifecycle:v1"

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.state in (Lifecycle.CLAIMED, Lifecycle.EXECUTING) and self.claim is None:
            raise ValueError("Active lifecycle requires a claim")
        if self.state == Lifecycle.EXECUTING and self.invocation_started_at is None:
            raise ValueError("Executing requires durable invocation boundary")
        if self.state in (Lifecycle.PENDING, Lifecycle.CLAIMED) and self.invocation_started_at:
            raise ValueError("Pre-invocation state cannot contain an invocation")
        if self.state == Lifecycle.SUCCEEDED and self.invocation_started_at is None:
            raise ValueError("Success requires an invocation boundary")
        return self


class ReconciledOutcome(StrEnum):
    CONFIRMED_SUCCEEDED = "confirmed_succeeded"
    CONFIRMED_FAILED = "confirmed_failed"
    UNRESOLVED = "unresolved"


class ReconciliationRequest(Frozen):
    execution_intent_id: Hash
    incident_id: UUID
    expected_revision: int = Field(ge=0, strict=True)
    previous_state: Literal[Lifecycle.UNCERTAIN] = Lifecycle.UNCERTAIN
    outcome: ReconciledOutcome
    reason: Text
    references: tuple[Text, ...] = Field(min_length=1)


class ReconciliationRecord(Frozen):
    request: ReconciliationRequest
    actor: Subject
    created_at: UTCTimestamp = Field(default_factory=utc_now)


class ExecutionEvent(Frozen):
    event_id: UUID = Field(default_factory=uuid4)
    event_type: Literal[
        "intent_created",
        "claimed",
        "invocation_boundary",
        "succeeded",
        "failed",
        "uncertain",
        "recovered",
        "reconciled",
    ]
    record: ExecutionRecord
    reconciliation: ReconciliationRecord | None = None
    occurred_at: UTCTimestamp = Field(default_factory=utc_now)
