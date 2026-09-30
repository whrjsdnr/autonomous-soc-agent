"""Bounded source reports, not proof of an attack or trusted incident severity."""

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator

from soc_agent.review.models import Frozen, Hash
from soc_agent.security_ai.authentication.aggregation import AuthenticationEvent
from soc_agent.state.enums import Severity
from soc_agent.state.evidence import UTCTimestamp

Reference = Annotated[
    str, StringConstraints(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:@/-]+$")
]


class AuthenticationAttributes(Frozen):
    attempts: tuple[AuthenticationEvent, ...] = Field(min_length=1, max_length=256)


class SOCEvent(Frozen):
    event_id: UUID
    event_type: Literal["authentication"]
    source: Reference
    occurred_at: UTCTimestamp
    subject: Reference
    resource: Reference
    severity_hint: Severity | None = None
    synthetic: bool = Field(default=False, strict=True)
    attributes: AuthenticationAttributes

    @model_validator(mode="after")
    def source_consistency(self) -> Self:
        attempts = self.attributes.attempts
        if len({a.event_id for a in attempts}) != len(attempts):
            raise ValueError("Duplicate attempt identity")
        for attempt in attempts:
            if attempt.account_id != self.subject or attempt.event_time > self.occurred_at:
                raise ValueError("Attempt differs from envelope subject/time")
            if any(
                len(v) > 128
                for v in (attempt.event_id, attempt.account_id, attempt.source_identifier)
            ):
                raise ValueError("Source reference too long")
        return self


class IngestionReceipt(Frozen):
    event: SOCEvent
    incident_id: UUID
    canonical_digest: Hash
    ingestion_version: Literal["authentication-ingestion:v1"] = "authentication-ingestion:v1"
    received_at: UTCTimestamp


class IngestionResult(Frozen):
    incident_id: UUID
    event_id: UUID
    canonical_digest: Hash
    ingestion_version: str
    duplicate: bool
