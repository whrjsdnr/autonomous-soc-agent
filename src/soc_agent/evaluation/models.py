"""Descriptive operational facts, never correctness judgments or authority."""

from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.experience.models import GovernanceOutcome, HistoricalOutcome
from soc_agent.investigation.runtime.models import WorkflowFailure, WorkflowStep
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.state.evidence import UTCTimestamp, utc_now

EVALUATOR_VERSION = "soc-outcome-evaluator:v1"


class EvaluationContent(Frozen):
    evaluator_version: Literal["soc-outcome-evaluator:v1"] = EVALUATOR_VERSION
    experience_id: Hash
    experience_digest: Hash
    incident_id: UUID
    run_id: UUID
    trace_digest: Hash
    current_step: WorkflowStep
    next_step: WorkflowStep
    terminal: bool
    waiting_for_human: bool
    workflow_failure: WorkflowFailure | None
    orchestration_step_count: int = Field(ge=1)
    recovery_observed: bool
    governance_outcome: GovernanceOutcome
    human_review_observed: bool
    human_rejected: bool
    governance_blocked: bool
    policy_deny_observed: bool
    # Preflight DENY does not prove that an execution was actually blocked by Policy.
    policy_blocked: None = None
    execution_outcome: HistoricalOutcome
    execution_attempted: bool | None
    invocation_boundary_observed: bool | None
    execution_failed: bool
    execution_uncertain: bool
    uncertain_observed: bool
    reconciliation_observed: bool
    investigation_rounds_recorded: int = Field(ge=0)
    investigation_count: None = None
    analysis_observed: bool
    fusion_observed: bool
    tool_call_count: None = None
    workflow_started_at: UTCTimestamp | None
    workflow_completed_at: UTCTimestamp | None
    duration_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.terminal != (self.next_step == WorkflowStep.COMPLETE):
            raise ValueError("Workflow terminal/cursor mismatch")
        if self.terminal and self.waiting_for_human:
            raise ValueError("Waiting is not terminal")
        if self.human_rejected != (self.governance_outcome == GovernanceOutcome.HUMAN_REJECTED):
            raise ValueError("Human rejection outcome mismatch")
        if self.governance_blocked != (self.governance_outcome == GovernanceOutcome.BLOCKED):
            raise ValueError("Governance blocking outcome mismatch")
        if self.execution_failed != (self.execution_outcome == HistoricalOutcome.FAILED):
            raise ValueError("Execution failure outcome mismatch")
        if self.execution_uncertain != (self.execution_outcome == HistoricalOutcome.UNCERTAIN):
            raise ValueError("Uncertain is not failed")
        start, end = self.workflow_started_at, self.workflow_completed_at
        if start is None or end is None:
            if self.duration_seconds is not None:
                raise ValueError("Duration requires both trusted timestamps")
        elif end < start or self.duration_seconds != (end - start).total_seconds():
            raise ValueError("Invalid workflow duration")
        return self


class EvaluationRecord(Frozen):
    evaluation_id: Hash
    content: EvaluationContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.evaluation_id != content_digest(self.content):
            raise ValueError("Evaluation content identity mismatch")
        return self
