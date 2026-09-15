"""Immutable AI execution records, separate from observed incident state."""

from enum import StrEnum
from typing import Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from soc_agent.security_ai.models import SecurityAIResult
from soc_agent.security_ai.selection_models import (
    SecurityAISelectionDecision,
    SecurityAISelectionStep,
)
from soc_agent.security_ai.signals import AISignal
from soc_agent.state.evidence import NonEmptyText, UTCTimestamp, utc_now


class SecurityAIInvestigationStepStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class SecurityAIInvestigationStep(BaseModel):
    """Selection snapshot plus one attempt; result may survive signal conversion failure."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    selection: SecurityAISelectionStep
    source_evidence_ids: tuple[UUID, ...] = ()
    status: SecurityAIInvestigationStepStatus = SecurityAIInvestigationStepStatus.PENDING
    result: SecurityAIResult | None = None
    signal: AISignal | None = None
    started_at: UTCTimestamp | None = None
    completed_at: UTCTimestamp | None = None
    error_type: NonEmptyText | None = None
    error_message: NonEmptyText | None = None

    @property
    def selection_step_id(self) -> UUID:
        return self.selection.step_id

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        status = self.status
        failed = status in (
            SecurityAIInvestigationStepStatus.FAILED,
            SecurityAIInvestigationStepStatus.BLOCKED,
        )
        if failed != (self.error_type is not None) or failed != (self.error_message is not None):
            raise ValueError("Only failed/blocked steps have error details")
        pending = status == SecurityAIInvestigationStepStatus.PENDING
        if pending != (self.completed_at is None):
            raise ValueError("Terminal steps require completion time")
        attempted = status in (
            SecurityAIInvestigationStepStatus.COMPLETED,
            SecurityAIInvestigationStepStatus.FAILED,
        )
        if attempted != (self.started_at is not None):
            raise ValueError("Only attempted steps have start time")
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise ValueError("Completion precedes start")
        if status == SecurityAIInvestigationStepStatus.COMPLETED:
            if self.result is None or self.signal is None:
                raise ValueError("Completed steps require both result and signal")
        elif self.signal is not None:
            raise ValueError("Only completed steps have signals")
        if not attempted and self.result is not None:
            raise ValueError("Unattempted steps cannot have results")
        if self.result is not None:
            for field in ("model_name", "model_version", "task_type"):
                if getattr(self.result, field) != getattr(self.selection, field):
                    raise ValueError("Result metadata differs from selected metadata")
        if self.signal is not None:
            result = self.result
            if result is None:
                raise ValueError("Signal requires a result")
            if self.signal.source_result_id != result.result_id:
                raise ValueError("Signal references a different result")
            for field in (
                "incident_id",
                "model_name",
                "model_version",
                "task_type",
                "prediction",
                "confidence",
                "scores",
                "explanation",
            ):
                if getattr(self.signal, field) != getattr(result, field):
                    raise ValueError("Signal differs from its source result")
            if self.signal.source_created_at != result.created_at:
                raise ValueError("Signal source timestamp differs")
            if self.signal.source_evidence_ids != self.source_evidence_ids:
                raise ValueError("Signal source evidence differs from execution binding")
        return self


class SecurityAIInvestigationResult(BaseModel):
    """Returned execution snapshot; ordered collections are derived from step records.

    No duplicate storage of results/signals and no unchanged IncidentState copy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    investigation_id: UUID = Field(default_factory=uuid4)
    selection_plan_id: UUID
    incident_id: UUID
    decision: SecurityAISelectionDecision
    steps: tuple[SecurityAIInvestigationStep, ...] = Field(max_length=5)
    created_at: UTCTimestamp = Field(default_factory=utc_now)
    completed_at: UTCTimestamp = Field(default_factory=utc_now)

    @property
    def results(self) -> tuple[SecurityAIResult, ...]:
        return tuple(step.result for step in self.steps if step.result is not None)

    @property
    def signals(self) -> tuple[AISignal, ...]:
        return tuple(step.signal for step in self.steps if step.signal is not None)

    @model_validator(mode="after")
    def validate_links(self) -> Self:
        if (self.decision == SecurityAISelectionDecision.RUN_AI) != bool(self.steps):
            raise ValueError("Decision and execution steps differ")
        if self.completed_at < self.created_at:
            raise ValueError("Investigation completion precedes creation")
        for ids in (
            [s.selection_step_id for s in self.steps],
            [r.result_id for r in self.results],
            [s.signal_id for s in self.signals],
        ):
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate execution identities")
        if any(result.incident_id != self.incident_id for result in self.results):
            raise ValueError("Result belongs to another incident")
        stopped = False
        failures = 0
        for step in self.steps:
            if (
                step.status
                in (
                    SecurityAIInvestigationStepStatus.COMPLETED,
                    SecurityAIInvestigationStepStatus.FAILED,
                )
                and stopped
            ):
                raise ValueError("Attempted step follows an unexecuted or failed step")
            if step.status != SecurityAIInvestigationStepStatus.COMPLETED:
                stopped = True
            if step.status in (
                SecurityAIInvestigationStepStatus.FAILED,
                SecurityAIInvestigationStepStatus.BLOCKED,
            ):
                failures += 1
            if step.completed_at is not None and not (
                self.created_at <= step.completed_at <= self.completed_at
            ):
                raise ValueError("Step completion outside investigation interval")
        if stopped and failures == 0:
            raise ValueError("Pending steps require a failure/block in a returned snapshot")
        if failures > 1:
            raise ValueError("Execution stops at the first failure/block")
        return self
