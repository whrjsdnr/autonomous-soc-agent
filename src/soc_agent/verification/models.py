"""Separate collection lifecycle, expected signals, and evidence-backed outcomes."""

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

from soc_agent.execution import ActionProposal
from soc_agent.investigation import StepFailure
from soc_agent.state import IncidentState
from soc_agent.state.evidence import Confidence, UTCTimestamp, utc_now
from soc_agent.tools.models import ToolName
from soc_agent.verification.errors import VerificationStepNotFoundError, VerificationStepStateError

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]


class VerificationStepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class VerificationOutcome(StrEnum):
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class VerificationStepDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_name: ToolName
    tool_input: dict[str, JsonValue]
    purpose: Text
    expected_signal: Text

    @field_validator("tool_input", mode="before")
    @classmethod
    def validate_json(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("Tool input must be a JSON object")
        ActionProposal.canonical_input(value)
        return value


class VerificationPlanDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    goal: Text
    steps: tuple[VerificationStepDraft, ...] = Field(min_length=1, max_length=5)


class VerificationStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    step_id: UUID = Field(default_factory=uuid4)
    verification_action_id: UUID = Field(default_factory=uuid4)
    tool_name: ToolName
    tool_input: str
    purpose: Text
    expected_signal: Text
    status: VerificationStepStatus = VerificationStepStatus.PENDING
    started_at: UTCTimestamp | None = None
    evidence_id: UUID | None = None
    failure: StepFailure | None = None

    @field_validator("tool_input", mode="before")
    @classmethod
    def canonical_input(cls, value: object) -> str:
        return ActionProposal.canonical_input(value)

    @model_validator(mode="after")
    def consistent_status(self) -> Self:
        if (self.status == VerificationStepStatus.COMPLETED) != (self.evidence_id is not None):
            raise ValueError("Only completed collection steps must reference evidence")
        if (self.status in (VerificationStepStatus.BLOCKED, VerificationStepStatus.FAILED)) != (
            self.failure is not None
        ):
            raise ValueError("Only blocked/failed steps must have failure details")
        if (self.status != VerificationStepStatus.PENDING) != (self.started_at is not None):
            raise ValueError("Attempted collection steps must have a start timestamp")
        return self

    def transition(
        self,
        status: VerificationStepStatus,
        *,
        evidence_id: UUID | None = None,
        failure: StepFailure | None = None,
    ) -> Self:
        allowed = {
            VerificationStepStatus.PENDING: (VerificationStepStatus.RUNNING,),
            VerificationStepStatus.BLOCKED: (VerificationStepStatus.RUNNING,),
            VerificationStepStatus.RUNNING: (
                VerificationStepStatus.COMPLETED,
                VerificationStepStatus.BLOCKED,
                VerificationStepStatus.FAILED,
            ),
        }
        if status not in allowed.get(self.status, ()):
            raise VerificationStepStateError("Invalid verification step transition")
        return type(self).model_validate(
            self.model_dump()
            | {
                "status": status,
                "evidence_id": evidence_id,
                "failure": failure,
                "started_at": utc_now()
                if status == VerificationStepStatus.RUNNING
                else self.started_at,
            }
        )


class VerificationPlan(BaseModel):
    """One completed response action; target snapshot detects same-ID input changes.

    baseline_evidence_ids excludes all evidence already present when planning began.
    IDs and frozen snapshots are application integrity, not signed execution receipts.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_plan_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    assessment_id: UUID
    response_plan_id: UUID
    response_step_id: UUID
    target_action: ActionProposal
    target_purpose: Text
    baseline_evidence_ids: tuple[UUID, ...]
    goal: Text
    steps: tuple[VerificationStep, ...] = Field(min_length=1, max_length=5)
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @property
    def target_action_id(self) -> UUID:
        return self.target_action.action_id

    @property
    def verification_evidence_ids(self) -> tuple[UUID, ...]:
        return tuple(s.evidence_id for s in self.steps if s.evidence_id is not None)

    @model_validator(mode="after")
    def validate_links(self) -> Self:
        if self.target_action.incident_id != self.incident_id:
            raise ValueError("Target action belongs to another incident")
        for ids in (
            [s.step_id for s in self.steps],
            [s.verification_action_id for s in self.steps],
            self.baseline_evidence_ids,
            self.verification_evidence_ids,
        ):
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate identities are forbidden")
        if self.target_action_id in {s.verification_action_id for s in self.steps}:
            raise ValueError("Collection action identity must differ from response identity")
        if set(self.baseline_evidence_ids) & set(self.verification_evidence_ids):
            raise ValueError("Baseline evidence cannot become verification evidence")
        if any(s.started_at is not None and s.started_at < self.created_at for s in self.steps):
            raise ValueError("Collection cannot precede verification planning")
        return self

    def get_step(self, step_id: UUID) -> VerificationStep:
        for step in self.steps:
            if step.step_id == step_id:
                return step
        raise VerificationStepNotFoundError("Verification step not found")

    def transition_step(
        self,
        step_id: UUID,
        status: VerificationStepStatus,
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
                "steps": tuple(updated if s.step_id == step_id else s for s in self.steps),
            }
        )


class VerificationResult(BaseModel):
    """Collection result only: it never declares mitigation success or failure."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    incident_state: IncidentState
    plan: VerificationPlan

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.incident_state.incident_id != self.plan.incident_id:
            raise ValueError("Plan and incident differ")
        evidence = {e.evidence_id: e for e in self.incident_state.evidence}
        if not set(self.plan.baseline_evidence_ids) <= evidence.keys():
            raise ValueError("Baseline evidence is missing")
        for step in self.plan.steps:
            if step.evidence_id is None:
                continue
            record = evidence.get(step.evidence_id)
            if (
                record is None
                or record.tool_name != step.tool_name
                or record.source != f"tool:{step.tool_name}"
                or step.started_at is None
                or record.collected_at < step.started_at
                or record.observed_at < step.started_at
            ):
                raise ValueError("Evidence does not match verification collection provenance")
        return self


class VerificationAssessmentDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    outcome: VerificationOutcome
    confidence: Confidence
    summary: Text
    supporting_evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=5)

    @field_validator("supporting_evidence_ids")
    @classmethod
    def unique_references(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("Duplicate evidence references")
        return value


class VerificationAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_id: UUID = Field(default_factory=uuid4)
    verification_plan_id: UUID
    incident_id: UUID
    assessment_id: UUID
    response_plan_id: UUID
    response_step_id: UUID
    target_action_id: UUID
    outcome: VerificationOutcome
    confidence: Confidence
    summary: Text
    supporting_evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=5)
    created_at: UTCTimestamp = Field(default_factory=utc_now)
