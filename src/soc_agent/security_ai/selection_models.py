"""Semantic selection drafts and application-bound immutable planning snapshots."""

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.enums import SecurityAIInputType, SecurityAITaskType
from soc_agent.security_ai.models import ModelName
from soc_agent.state.evidence import NonEmptyText, UTCTimestamp, utc_now

SelectionText = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)
]


class SecurityAISelectionDecision(StrEnum):
    RUN_AI = "run_ai"
    NO_AI_NEEDED = "no_ai_needed"


def _check_decision(decision: SecurityAISelectionDecision, count: int) -> None:
    if (decision == SecurityAISelectionDecision.RUN_AI) != (count > 0):
        raise ValueError("RUN_AI requires selections; NO_AI_NEEDED requires none")


class SecurityAISelectionStepDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    model_name: ModelName
    model_input: dict[str, JsonValue]
    purpose: SelectionText

    @field_validator("model_input", mode="before")
    @classmethod
    def require_json_object(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("Model input must be a JSON object")
        canonical_json_object(value)
        return value


class SecurityAISelectionDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    decision: SecurityAISelectionDecision
    goal: SelectionText
    reason: SelectionText
    selections: tuple[SecurityAISelectionStepDraft, ...] = Field(max_length=5)

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        _check_decision(self.decision, len(self.selections))
        return self


class SecurityAISelectionStep(BaseModel):
    """Registry metadata and validated input; purpose remains untrusted reasoning."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    step_id: UUID = Field(default_factory=uuid4)
    model_name: ModelName
    model_version: NonEmptyText
    task_type: SecurityAITaskType
    input_type: SecurityAIInputType
    model_input: str
    purpose: SelectionText

    @field_validator("model_input", mode="before")
    @classmethod
    def freeze_input(cls, value: object) -> str:
        return canonical_json_object(value)

    def input_payload(self) -> dict[str, JsonValue]:
        return TypeAdapter(dict[str, JsonValue]).validate_json(self.model_input, strict=True)


class SecurityAISelectionPlan(BaseModel):
    """Planning only. Direct construction validates shape, not registry authenticity."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    plan_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    decision: SecurityAISelectionDecision
    goal: SelectionText
    reason: SelectionText
    steps: tuple[SecurityAISelectionStep, ...] = Field(max_length=5)
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_steps(self) -> Self:
        _check_decision(self.decision, len(self.steps))
        ids = [step.step_id for step in self.steps]
        keys = [(step.model_name, step.model_input) for step in self.steps]
        if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
            raise ValueError("Duplicate selection IDs or model/input pairs are not allowed")
        return self
