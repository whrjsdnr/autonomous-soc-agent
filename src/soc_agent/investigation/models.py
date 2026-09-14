"""Immutable investigation plans and explicit step lifecycle snapshots."""

from enum import StrEnum
from typing import Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from soc_agent.execution import ActionProposal
from soc_agent.investigation.errors import (
    InvestigationStepNotFoundError,
    InvestigationStepStateError,
)
from soc_agent.state import IncidentState
from soc_agent.state.evidence import NonEmptyText, UTCTimestamp, utc_now
from soc_agent.tools.models import ToolName


class InvestigationStepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class StepFailure(BaseModel):
    """Preserve the originating error type and message without storing exceptions."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    error_type: NonEmptyText
    reason: NonEmptyText


class InvestigationStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: UUID = Field(default_factory=uuid4)
    action_id: UUID = Field(default_factory=uuid4)
    tool_name: ToolName
    tool_input: str
    purpose: NonEmptyText
    status: InvestigationStepStatus = InvestigationStepStatus.PENDING
    evidence_id: UUID | None = None
    failure: StepFailure | None = None

    @field_validator("tool_input", mode="before")
    @classmethod
    def normalize_input(cls, value: object) -> str:
        return ActionProposal.canonical_input(value)

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (self.status == InvestigationStepStatus.COMPLETED) != (self.evidence_id is not None):
            raise ValueError("Only completed steps must reference evidence")
        failed = self.status in (InvestigationStepStatus.FAILED, InvestigationStepStatus.BLOCKED)
        if failed != (self.failure is not None):
            raise ValueError("Only blocked/failed steps must contain failure details")
        return self

    def transition(
        self,
        status: InvestigationStepStatus,
        *,
        evidence_id: UUID | None = None,
        failure: StepFailure | None = None,
    ) -> Self:
        allowed = {
            InvestigationStepStatus.PENDING: (InvestigationStepStatus.RUNNING,),
            InvestigationStepStatus.BLOCKED: (InvestigationStepStatus.RUNNING,),
            InvestigationStepStatus.RUNNING: (
                InvestigationStepStatus.COMPLETED,
                InvestigationStepStatus.FAILED,
                InvestigationStepStatus.BLOCKED,
            ),
        }
        if status not in allowed.get(self.status, ()):
            raise InvestigationStepStateError("Invalid investigation step transition")
        return type(self).model_validate(
            self.model_dump()
            | {
                "status": status,
                "evidence_id": evidence_id,
                "failure": failure,
            }
        )


class InvestigationPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    steps: tuple[InvestigationStep, ...] = Field(min_length=1)
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def unique_identities(self) -> Self:
        for ids in ([s.step_id for s in self.steps], [s.action_id for s in self.steps]):
            if len(ids) != len(set(ids)):
                raise ValueError("Step IDs and action IDs must each be unique within a plan")
        return self

    def get_step(self, step_id: UUID) -> InvestigationStep:
        for step in self.steps:
            if step.step_id == step_id:
                return step
        raise InvestigationStepNotFoundError("Investigation step not found")

    def transition_step(
        self,
        step_id: UUID,
        status: InvestigationStepStatus,
        *,
        evidence_id: UUID | None = None,
        failure: StepFailure | None = None,
    ) -> Self:
        updated = self.get_step(step_id).transition(
            status, evidence_id=evidence_id, failure=failure
        )
        return type(self).model_validate(
            self.model_dump()
            | {
                "steps": tuple(updated if step.step_id == step_id else step for step in self.steps),
            }
        )


class InvestigationResult(BaseModel):
    """Returned state and plan; step records link action IDs to evidence IDs."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    incident_state: IncidentState
    plan: InvestigationPlan
