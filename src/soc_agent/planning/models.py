"""Untrusted semantic drafts and explicitly projected planner context."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from soc_agent.execution import ActionProposal
from soc_agent.state import Hypothesis, IncidentStatus, Observation, Severity
from soc_agent.state.evidence import NonEmptyText
from soc_agent.tools import ToolMetadata
from soc_agent.tools.models import ToolName


class LLMInvestigationStepDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_name: ToolName
    tool_input: dict[str, JsonValue]
    purpose: NonEmptyText

    @field_validator("tool_input", mode="before")
    @classmethod
    def require_json_object(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("Draft tool input must be a JSON object")
        # Reuse canonicalization for JSON compatibility (including rejecting NaN).
        ActionProposal.canonical_input(value)
        return value


class LLMInvestigationPlanDraft(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    goal: NonEmptyText
    steps: tuple[LLMInvestigationStepDraft, ...] = Field(min_length=1, max_length=8)


class EvidenceContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    evidence_id: UUID
    source: str
    summary: str
    tool_name: str | None


class ToolCatalogEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    metadata: ToolMetadata
    input_schema_json: str


class PlannerInput(BaseModel):
    """No raw evidence; hypotheses remain explicitly separate from facts."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    incident_id: UUID
    status: IncidentStatus
    severity: Severity
    evidence: tuple[EvidenceContext, ...]
    observations: tuple[Observation, ...]
    hypotheses: tuple[Hypothesis, ...]
    tools: tuple[ToolCatalogEntry, ...]
