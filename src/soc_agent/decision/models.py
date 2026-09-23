"""Immutable review artifact with separate source and model lineage."""

import hashlib
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from soc_agent._json import canonical_json_object
from soc_agent.assessment.models import ThreatAssessment
from soc_agent.decision.rules import DecisionOutcome
from soc_agent.security_ai.fusion.models import FusionResult
from soc_agent.state import Hypothesis, Observation


def fingerprint(payload: dict[str, JsonValue]) -> str:
    # Retain upstream reference identities, but not their creation clocks.
    def without_clocks(value: JsonValue) -> JsonValue:
        if isinstance(value, dict):
            return {k: without_clocks(v) for k, v in value.items() if k != "created_at"}
        if isinstance(value, list):
            return [without_clocks(v) for v in value]
        return value

    return hashlib.sha256(canonical_json_object(without_clocks(payload)).encode()).hexdigest()


class IncidentDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    decision_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_version: Literal["1.0.0"] = "1.0.0"
    rule_version: Literal["incident-decision:v1"] = "incident-decision:v1"
    incident_id: UUID
    outcome: DecisionOutcome
    assessment: ThreatAssessment
    evidence_ids: tuple[UUID, ...]
    observations: tuple[Observation, ...]
    hypotheses: tuple[Hypothesis, ...]
    model_derived_context: FusionResult | None
    applied_rules: tuple[str, ...]
    rationale: tuple[str, ...]
    uncertainties: tuple[str, ...]
    additional_investigation_required: bool
    investigation_reasons: tuple[str, ...]
    review_reasons: tuple[str, ...]
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def check_identity(self) -> Self:
        if self.assessment.incident_id != self.incident_id:
            raise ValueError("Decision assessment incident mismatch")
        if (
            self.model_derived_context
            and self.model_derived_context.incident_id != self.incident_id
        ):
            raise ValueError("Decision fusion incident mismatch")
        if self.decision_id != fingerprint(self.model_dump(mode="json", exclude={"decision_id"})):
            raise ValueError("Decision identity mismatch")
        return self
