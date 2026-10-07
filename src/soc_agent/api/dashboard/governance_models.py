"""Strict presentation/command DTOs; no body field conveys human authority."""

from enum import StrEnum
from uuid import UUID

from pydantic import Field, field_validator

from soc_agent.api.dashboard.incident_query import display_text
from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.models import Frozen, Hash, ReviewOutcome, Subject
from soc_agent.state.evidence import UTCTimestamp


class GovernanceDomain(StrEnum):
    INCIDENT_REVIEW = "incident-reviews"
    STATE_AUTHORIZATION = "state-authorizations"


class GovernanceActionView(Frozen):
    domain: GovernanceDomain
    request_id: UUID
    incident_id: UUID
    request_digest: Hash
    status: str
    summary: tuple[str, ...]
    current_state: tuple[str, ...]
    proposed_state: tuple[str, ...]
    basis: tuple[str, ...]
    required_permission: str
    decision_options: tuple[str, ...]
    created_at: UTCTimestamp | None
    confirmation_required: bool = True
    risk: str = "UNKNOWN"
    impact: str = "UNKNOWN"
    actionable: bool


class GovernanceInbox(Frozen):
    actions: tuple[GovernanceActionView, ...]
    unavailable: tuple[str, ...] = (
        "Response Action Review: pending intents are memory-only; read-only in Incident Detail.",
        "Tool Approval: pending requests are memory-only; read-only durable intent snapshots.",
        "Durable Reconciliation: no durable pending attestation request; not a retry action.",
    )


class ReviewDecisionInput(Frozen):
    expected_request_digest: Hash
    outcome: ReviewOutcome
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def safe_note(cls, value: str) -> str:
        value = value.strip()
        if not value or display_text(value) != value:
            raise ValueError("Bounded non-credential human reason required")
        return value


class StateAuthorizationInput(Frozen):
    expected_request_digest: Hash


class ConfirmationFields(Frozen):
    confirmation_id: Subject
    expected_confirmation_digest: Hash


class SubmitReviewDecision(ReviewDecisionInput, ConfirmationFields):
    pass


class SubmitStateAuthorization(StateAuthorizationInput, ConfirmationFields):
    pass


class GovernanceConfirmationView(Frozen):
    action: GovernanceActionView
    context: HumanActionContext
    decision: str
    reason: str | None
    confirmation_id: Subject
    expires_at: UTCTimestamp
    subject_id: Subject
    session_id: Subject


class GovernanceResultView(Frozen):
    domain: GovernanceDomain
    incident_id: UUID
    request_id: UUID
    record_id: UUID
    decision: str
    recorded_at: UTCTimestamp
    state_applied: bool = False
