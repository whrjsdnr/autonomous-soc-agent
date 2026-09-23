"""Review facts, proposals and state authorizations are different frozen contracts."""

from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from soc_agent.state import IncidentState, IncidentStatus, Severity
from soc_agent.state.evidence import UTCTimestamp, utc_now

Hash = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
Subject = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
TransitionVersion = Literal["incident-state-transition:v1"]


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class StateAnchor(Frozen):
    repository_id: UUID
    incident_id: UUID
    revision: int = Field(ge=0, strict=True)
    fingerprint: Hash


class StoredIncident(Frozen):
    state: IncidentState
    anchor: StateAnchor


class ReviewTarget(Frozen):
    incident_id: UUID
    decision_id: Hash
    decision_digest: Hash
    decision_version: Literal["1.0.0"]
    decision_rule_version: Literal["incident-decision:v1"]
    snapshot: StateAnchor

    @model_validator(mode="after")
    def incident_matches(self) -> Self:
        if self.incident_id != self.snapshot.incident_id:
            raise ValueError("Review target incident differs from snapshot")
        return self


class HumanReviewRequest(Frozen):
    review_request_id: UUID = Field(default_factory=uuid4)
    target: ReviewTarget
    created_at: UTCTimestamp = Field(default_factory=utc_now)


class ReviewOutcome(StrEnum):
    ACKNOWLEDGED = "acknowledged_without_authorization"
    INVESTIGATE = "additional_investigation_requested"
    REJECTED = "state_change_rejected"
    CHANGE_ELIGIBLE = "state_change_may_be_proposed"


class ReviewIntent(Frozen):
    review_request_id: UUID
    target: ReviewTarget
    reviewer_id: Subject
    outcome: ReviewOutcome
    reason: Text

    @property
    def additional_investigation_requested(self) -> bool:
        return self.outcome == ReviewOutcome.INVESTIGATE


class HumanReviewRecord(ReviewIntent):
    review_id: UUID = Field(default_factory=uuid4)
    recorded_at: UTCTimestamp = Field(default_factory=utc_now)


class StatusChange(Frozen):
    field: Literal["status"] = "status"
    before: IncidentStatus
    after: IncidentStatus


class SeverityChange(Frozen):
    field: Literal["severity"] = "severity"
    before: Severity
    after: Severity


StateChange = Annotated[StatusChange | SeverityChange, Field(discriminator="field")]


class StateChangeRequest(Frozen):
    request_id: UUID = Field(default_factory=uuid4)
    target: ReviewTarget
    review_id: UUID
    changes: tuple[StateChange, ...] = Field(min_length=1, max_length=2)
    reason: Text
    transition_version: TransitionVersion = "incident-state-transition:v1"

    @field_validator("changes")
    @classmethod
    def canonical_changes(cls, changes: tuple[StateChange, ...]) -> tuple[StateChange, ...]:
        if len({c.field for c in changes}) != len(changes):
            raise ValueError("Duplicate changed field")
        if any(c.before == c.after for c in changes):
            raise ValueError("No-op changes are not authorized")
        return tuple(sorted(changes, key=lambda c: c.field))


class StateChangeAuthorization(Frozen):
    kind: Literal["incident_state_change"] = "incident_state_change"
    authorization_id: UUID = Field(default_factory=uuid4)
    request: StateChangeRequest
    request_digest: Hash
    authorized_by: Subject
    issued_at: UTCTimestamp = Field(default_factory=utc_now)


class ApplicationAudit(Frozen):
    application_id: UUID = Field(default_factory=uuid4)
    target: ReviewTarget
    review_id: UUID
    request_id: UUID
    authorization_id: UUID
    authorized_by: Subject
    changes: tuple[StateChange, ...]
    transition_version: TransitionVersion = "incident-state-transition:v1"
    outcome: Literal["applied"] = "applied"
    resulting_snapshot: StateAnchor
    applied_at: UTCTimestamp


class ApplicationResult(Frozen):
    incident_state: IncidentState
    audit: ApplicationAudit


class ApplicationFailure(Frozen):
    attempt_id: UUID = Field(default_factory=uuid4)
    outcome: Literal["failed"] = "failed"
    registered_request: StateChangeRequest | None
    authorization_id: UUID | None
    error_type: Text
    reason: Text
    recorded_at: UTCTimestamp = Field(default_factory=utc_now)
