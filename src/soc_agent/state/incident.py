"""Explicit incident snapshots with validated, append-only additions."""

from typing import Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from soc_agent.state.enums import IncidentStatus, Severity
from soc_agent.state.evidence import (
    Confidence,
    Evidence,
    Hypothesis,
    Observation,
    UTCTimestamp,
    utc_now,
)


class IncidentState(BaseModel):
    """Source of truth for one incident.

    Additions return a new validated snapshot: use state = state.add_evidence(record).
    Frozen nested records and tuples prevent ordinary in-place edits. Pydantic's
    model_construct/model_copy(update=...) bypass validation and must not be used
    for untrusted data. Workflow transitions belong to a later phase.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: UUID = Field(default_factory=uuid4)
    status: IncidentStatus = IncidentStatus.NEW
    severity: Severity = Severity.INFO
    confidence: Confidence | None = None
    evidence: tuple[Evidence, ...] = ()
    observations: tuple[Observation, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    created_at: UTCTimestamp = Field(default_factory=utc_now)
    updated_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        evidence_ids = [item.evidence_id for item in self.evidence]
        observation_ids = [item.observation_id for item in self.observations]
        hypothesis_ids = [item.hypothesis_id for item in self.hypotheses]
        for ids in (evidence_ids, observation_ids, hypothesis_ids):
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate record IDs are not allowed")
        if any(item.incident_id != self.incident_id for item in self.evidence):
            raise ValueError("Evidence must belong to this incident")
        known_ids = set(evidence_ids)
        for record in (*self.observations, *self.hypotheses):
            if not set(record.supporting_evidence_ids) <= known_ids:
                raise ValueError("Supporting evidence must exist in this incident")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        return self

    def add_evidence(self, evidence: Evidence) -> Self:
        """Append evidence without overwriting an existing record."""
        return self._append("evidence", evidence)

    def add_observation(self, observation: Observation) -> Self:
        """Append a fact only when its supporting evidence is present."""
        return self._append("observations", observation)

    def add_hypothesis(self, hypothesis: Hypothesis) -> Self:
        """Append an interpretation separately from confirmed records."""
        return self._append("hypotheses", hypothesis)

    def _append(self, field: str, record: Evidence | Observation | Hypothesis) -> Self:
        data = self.model_dump()
        data[field] = (*data[field], record)
        data["updated_at"] = max(utc_now(), self.updated_at)
        return type(self).model_validate(data)
