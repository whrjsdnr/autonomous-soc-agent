"""Immutable response plans and explicit step lifecycle snapshots."""

from enum import StrEnum
from typing import Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from soc_agent.execution import ActionProposal
from soc_agent.response.errors import (
    ResponseStepNotFoundError,
    ResponseStepStateError,
)
from soc_agent.state import IncidentState
from soc_agent.state.evidence import NonEmptyText, UTCTimestamp, utc_now
from soc_agent.tools.models import ToolName


class ResponseStepStatus(StrEnum):
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class StepFailure(BaseModel):
    """Preserve the originating error type and message without storing exceptions."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    error_type: NonEmptyText
    reason: NonEmptyText


class ResponseStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: UUID = Field(default_factory=uuid4)
    action_id: UUID = Field(default_factory=uuid4)
    tool_name: ToolName
    tool_input: str
    purpose: NonEmptyText
    status: ResponseStepStatus = ResponseStepStatus.PENDING
    failure: StepFailure | None = None

    @field_validator("tool_input", mode="before")
    @classmethod
    def normalize_input(cls, value: object) -> str:
        return ActionProposal.canonical_input(value)

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        failed = self.status in (ResponseStepStatus.FAILED, ResponseStepStatus.BLOCKED)
        if failed != (self.failure is not None):
            raise ValueError("Only blocked/failed steps must contain failure details")
        return self

    def transition(
        self,
        status: ResponseStepStatus,
        *,
        failure: StepFailure | None = None,
    ) -> Self:
        allowed = {
            ResponseStepStatus.PENDING: (ResponseStepStatus.EXECUTING,),
            ResponseStepStatus.BLOCKED: (ResponseStepStatus.EXECUTING,),
            ResponseStepStatus.EXECUTING: (
                ResponseStepStatus.COMPLETED,
                ResponseStepStatus.FAILED,
                ResponseStepStatus.BLOCKED,
            ),
        }
        if status not in allowed.get(self.status, ()):
            raise ResponseStepStateError("Invalid response step transition")
        return type(self).model_validate(
            self.model_dump()
            | {
                "status": status,
                "failure": failure,
            }
        )


class ResponsePlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    assessment_id: UUID
    goal: NonEmptyText
    steps: tuple[ResponseStep, ...] = Field(min_length=1, max_length=5)
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def unique_identities(self) -> Self:
        for ids in ([s.step_id for s in self.steps], [s.action_id for s in self.steps]):
            if len(ids) != len(set(ids)):
                raise ValueError("Step IDs and action IDs must each be unique within a plan")
        return self

    def get_step(self, step_id: UUID) -> ResponseStep:
        for step in self.steps:
            if step.step_id == step_id:
                return step
        raise ResponseStepNotFoundError("Response step not found")

    def transition_step(
        self,
        step_id: UUID,
        status: ResponseStepStatus,
        *,
        failure: StepFailure | None = None,
    ) -> Self:
        updated = self.get_step(step_id).transition(status, failure=failure)
        return type(self).model_validate(
            self.model_dump()
            | {
                "steps": tuple(updated if step.step_id == step_id else step for step in self.steps),
            }
        )


class ResponseResult(BaseModel):
    """Unchanged incident and response progress; completion is not mitigation verification."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    incident_state: IncidentState
    plan: ResponsePlan

    @model_validator(mode="after")
    def validate_incident_binding(self) -> Self:
        if self.incident_state.incident_id != self.plan.incident_id:
            raise ValueError("Response plan and state incident IDs differ")
        return self


class ResponseStepDraft(BaseModel):
    """Untrusted semantic proposal; contains no authority or application IDs."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_name: ToolName
    tool_input: dict[str, JsonValue]
    purpose: NonEmptyText

    @field_validator("tool_input", mode="before")
    @classmethod
    def require_json_object(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("Draft tool input must be a JSON object")
        ActionProposal.canonical_input(value)
        return value


class ResponsePlanDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    goal: NonEmptyText
    steps: tuple[ResponseStepDraft, ...] = Field(min_length=1, max_length=5)
