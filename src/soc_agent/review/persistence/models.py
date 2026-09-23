"""Persistent governance events and explicit storage failure categories."""

from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field

from soc_agent.review.errors import ReviewError
from soc_agent.review.models import (
    ApplicationResult,
    Frozen,
    StateAnchor,
    StateChange,
    StateChangeAuthorization,
)
from soc_agent.state.evidence import UTCTimestamp, utc_now


class StorageError(ReviewError):
    """Database failure with no committed mutation from this transaction."""


class StoredDataError(StorageError):
    """Stored structure, digest or reference graph is invalid; no default recovery."""


class UnsupportedSchemaError(StorageError):
    pass


class CommitOutcomeUnknown(ReviewError):
    """Do not retry blindly; query authorization/application using a fresh connection."""


class FailureAuditUnavailable(StorageError):
    """Original operation failed and its separate failure audit could not be persisted."""


EventType = Literal[
    "incident_registered",
    "evidence_appended",
    "review_requested",
    "review_recorded",
    "change_requested",
    "authorization_issued",
    "authorization_rejected",
    "review_rejected",
    "application_succeeded",
    "application_failed",
    "application_outcome_unknown",
    "transaction_outcome_unknown",
]


class GovernanceEvent(Frozen):
    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    incident_id: UUID | None = None
    decision_id: str | None = None
    review_id: UUID | None = None
    request_id: UUID | None = None
    authorization_id: UUID | None = None
    actor_id: str | None = None
    before: StateAnchor | None = None
    after: StateAnchor | None = None
    changes: tuple[StateChange, ...] = ()
    rule_version: str | None = None
    failure_type: str | None = None
    occurred_at: UTCTimestamp = Field(default_factory=utc_now)


class AuthorizationStatus(Frozen):
    authorization: StateChangeAuthorization
    consumed: bool
    application: ApplicationResult | None
