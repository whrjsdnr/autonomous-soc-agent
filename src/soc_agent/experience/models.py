"""Reference-only historical records. These objects convey no execution authority."""

from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.execution.durable.models import Lifecycle, ReconciledOutcome
from soc_agent.investigation.runtime.models import WorkflowFailure, WorkflowStep
from soc_agent.policy import PolicyDecision
from soc_agent.response.promotion.models import ReviewDisposition
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash, ReviewOutcome, StateAnchor
from soc_agent.state import IncidentStatus, Severity
from soc_agent.state.evidence import UTCTimestamp, utc_now


class HistoricalOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    NOT_EXECUTED = "not_executed"


class GovernanceOutcome(StrEnum):
    HUMAN_REJECTED = "human_rejected"
    BLOCKED = "blocked"
    WAITING = "waiting_for_human"
    REVIEW_RECORDED = "review_recorded"
    NOT_RECORDED = "not_recorded"


class HistoricalReference(Frozen):
    kind: Literal[
        "evidence",
        "observation",
        "hypothesis",
        "assessment",
        "decision",
        "fusion",
        "signal",
        "investigation",
        "incident_review",
        "state_authorization",
        "response_plan",
        "proposal",
        "promoted_action",
        "response_review",
        "promotion_request",
        "tool_approval",
        "execution_intent",
        "execution_record",
        "execution_event",
    ]
    identity: UUID | Hash
    digest: Hash


class ExperienceContent(Frozen):
    version: Literal["experience:v1"] = "experience:v1"
    incident_id: UUID
    snapshot: StateAnchor
    status: IncidentStatus
    severity: Severity
    run_id: UUID
    trace_head: Hash
    trace_digest: Hash
    current_step: WorkflowStep
    next_step: WorkflowStep
    terminal: bool
    waiting_for_human: bool
    failure: WorkflowFailure | None
    governance_outcome: GovernanceOutcome
    policy_preflight_results: tuple[PolicyDecision, ...] = ()
    response_disposition: ReviewDisposition | None = None
    major_steps: tuple[WorkflowStep, ...]
    execution_outcome: HistoricalOutcome
    execution_lifecycle: Lifecycle | None = None
    execution_revision: int | None = Field(default=None, ge=0)
    reconciliation: ReconciledOutcome | None = None
    human_disposition: ReviewOutcome | None = None
    references: tuple[HistoricalReference, ...]
    orchestration_step_count: int = Field(ge=1)
    investigation_rounds: int = Field(ge=0)
    # No reliable aggregate invocation count or workflow completion clock exists yet.
    tool_invocation_count: None = None
    started_at: UTCTimestamp
    completed_at: None = None
    elapsed_seconds: None = None

    @model_validator(mode="after")
    def bindings(self) -> Self:
        if self.incident_id != self.snapshot.incident_id:
            raise ValueError("Experience incident mismatch")
        if self.terminal != (self.next_step == WorkflowStep.COMPLETE):
            raise ValueError("Experience terminal mismatch")
        if self.terminal and self.waiting_for_human:
            raise ValueError("Human waiting is not terminal")
        expected = {
            Lifecycle.SUCCEEDED: HistoricalOutcome.SUCCEEDED,
            Lifecycle.FAILED: HistoricalOutcome.FAILED,
            Lifecycle.EXECUTING: HistoricalOutcome.UNCERTAIN,
            Lifecycle.UNCERTAIN: HistoricalOutcome.UNCERTAIN,
        }.get(self.execution_lifecycle, HistoricalOutcome.NOT_EXECUTED)
        if self.execution_outcome != expected:
            raise ValueError("Historical execution outcome differs from lifecycle")
        if (self.execution_lifecycle is None) != (self.execution_revision is None):
            raise ValueError("Execution revision/lifecycle mismatch")
        keys = [(r.kind, str(r.identity)) for r in self.references]
        if keys != sorted(set(keys)):
            raise ValueError("Historical references must be unique and ordered")
        return self


class Experience(Frozen):
    experience_id: Hash
    content: ExperienceContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.experience_id != content_digest(self.content):
            raise ValueError("Experience identity/content mismatch")
        return self
