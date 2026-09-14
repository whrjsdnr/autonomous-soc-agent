"""Source records, directly observed facts, and unverified interpretations."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints

NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Confidence = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]


def utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


UTCTimestamp = Annotated[AwareDatetime, AfterValidator(_as_utc)]


class Evidence(BaseModel):
    """A source-confirmed record, never an agent interpretation.

    raw_data preserves the original textual record (including whitespace).
    source identifies its provenance; tool_name is absent for direct ingestion.
    Reliability is unknown unless explicitly supplied, not assumed trustworthy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    source: NonEmptyText
    summary: NonEmptyText
    raw_data: Annotated[str, Field(min_length=1)]
    observed_at: UTCTimestamp
    collected_at: UTCTimestamp = Field(default_factory=utc_now)
    tool_name: NonEmptyText | None = None
    reliability: Confidence | None = None


class Observation(BaseModel):
    """A fact directly supported by evidence, without attack attribution or speculation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: UUID = Field(default_factory=uuid4)
    statement: NonEmptyText
    supporting_evidence_ids: tuple[UUID, ...] = Field(min_length=1)
    created_at: UTCTimestamp = Field(default_factory=utc_now)


class Hypothesis(BaseModel):
    """An unverified interpretation; confidence does not promote it to evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hypothesis_id: UUID = Field(default_factory=uuid4)
    statement: NonEmptyText
    supporting_evidence_ids: tuple[UUID, ...] = Field(min_length=1)
    confidence: Confidence
    created_at: UTCTimestamp = Field(default_factory=utc_now)
