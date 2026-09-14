"""Immutable approval snapshots and explicit human decision records."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from soc_agent.tools.enums import ToolPermission, ToolRiskLevel
from soc_agent.tools.models import ToolName

NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


def utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


# Small local utility avoids coupling approval to state.evidence.
UTCTimestamp = Annotated[AwareDatetime, AfterValidator(_as_utc)]


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalDecision(BaseModel):
    """Recorded human input; decided_by is an attribution, not authentication."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal[ApprovalStatus.APPROVED, ApprovalStatus.REJECTED]
    decided_by: NonEmptyText
    decided_at: UTCTimestamp = Field(default_factory=utc_now)


class ApprovalRequest(BaseModel):
    """Incident-linked request snapshot, not an executable authorization token.

    Concrete action parameters and authorization binding belong to a future executor.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    tool_name: ToolName
    permission: ToolPermission
    risk_level: ToolRiskLevel
    reason: NonEmptyText
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: UTCTimestamp = Field(default_factory=utc_now)
    decision: ApprovalDecision | None = None

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if self.status == ApprovalStatus.PENDING:
            if self.decision is not None:
                raise ValueError("Pending request cannot have a decision")
        elif self.decision is None or self.decision.status != self.status:
            raise ValueError("Decided request must have a matching decision")
        if self.decision is not None and self.decision.decided_at < self.created_at:
            raise ValueError("Decision must not precede request creation")
        return self
