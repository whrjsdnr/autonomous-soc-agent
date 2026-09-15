"""Allowlist and schema validation; never duplicates policy rules."""

from collections.abc import Mapping
from uuid import UUID

from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticSerializationError

from soc_agent.assessment import AssessmentResult, ThreatAssessment
from soc_agent.execution import ActionProposal
from soc_agent.response.errors import (
    InvalidResponseReferenceError,
    ResponsePlanMismatchError,
    ResponsePlanningError,
)
from soc_agent.response.models import ResponsePlan, ResponsePlanDraft, ResponseStep
from soc_agent.state import IncidentState
from soc_agent.tools import Tool


def normalize_plan(
    draft: ResponsePlanDraft,
    *,
    incident_id: UUID,
    assessment_id: UUID,
    tools: Mapping[str, Tool[BaseModel, BaseModel]],
) -> ResponsePlan:
    try:
        # Frozen draft containers still contain JSON dictionaries; detach and revalidate.
        validated = ResponsePlanDraft.model_validate(draft.model_dump(warnings=False))
    except ValidationError as error:
        raise ResponsePlanningError("Invalid response draft") from error
    steps = []
    for step in validated.steps:
        if step.tool_name not in tools:
            raise ResponsePlanningError("Draft selected a tool outside the planning catalog")
        schema = tools[step.tool_name].input_model
        try:
            value = schema.model_validate(step.tool_input, extra="forbid")
            payload = value.model_dump(mode="json", by_alias=True, round_trip=True)
            canonical = ActionProposal.canonical_input(payload)
            # Ensure serialization remains acceptable on the actual execution path.
            schema.model_validate(payload, extra="forbid")
        except (ValueError, TypeError, PydanticSerializationError) as error:
            raise ResponsePlanningError("Planned tool input does not satisfy its schema") from error
        steps.append(
            ResponseStep(tool_name=step.tool_name, tool_input=canonical, purpose=step.purpose)
        )
    return ResponsePlan(
        incident_id=incident_id,
        assessment_id=assessment_id,
        goal=validated.goal,
        steps=tuple(steps),
    )


def validate_assessment(state: IncidentState, assessment: ThreatAssessment) -> AssessmentResult:
    """Revalidate nested snapshots before any LLM request, including bypass-built models."""
    if state.incident_id != assessment.incident_id:
        raise ResponsePlanMismatchError("Assessment and incident IDs differ")
    try:
        return AssessmentResult.model_validate(
            {
                "incident_state": state.model_dump(warnings=False),
                "threat_assessment": assessment.model_dump(warnings=False),
            }
        )
    except ValueError as error:
        raise InvalidResponseReferenceError("Invalid assessment or incident references") from error
