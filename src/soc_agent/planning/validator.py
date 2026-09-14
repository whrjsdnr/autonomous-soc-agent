"""Allowlist and schema validation; never duplicates policy rules."""

from collections.abc import Mapping
from uuid import UUID

from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticSerializationError

from soc_agent.execution import ActionProposal
from soc_agent.investigation import InvestigationPlan, InvestigationStep
from soc_agent.planning.errors import (
    InvalidPlanError,
    InvalidPlannedToolInputError,
    UnknownPlannedToolError,
)
from soc_agent.planning.models import LLMInvestigationPlanDraft
from soc_agent.tools import Tool


def normalize_plan(
    draft: LLMInvestigationPlanDraft,
    *,
    incident_id: UUID,
    tools: Mapping[str, Tool[BaseModel, BaseModel]],
) -> InvestigationPlan:
    try:
        # Frozen draft containers still contain JSON dictionaries; detach and revalidate.
        validated = LLMInvestigationPlanDraft.model_validate(draft.model_dump(warnings=False))
    except ValidationError as error:
        raise InvalidPlanError("Invalid investigation draft") from error
    steps = []
    for step in validated.steps:
        if step.tool_name not in tools:
            raise UnknownPlannedToolError("Draft selected a tool outside the planning catalog")
        schema = tools[step.tool_name].input_model
        try:
            value = schema.model_validate(step.tool_input, extra="forbid")
            payload = value.model_dump(mode="json", by_alias=True, round_trip=True)
            canonical = ActionProposal.canonical_input(payload)
            # Ensure serialization remains acceptable on the actual execution path.
            schema.model_validate(payload, extra="forbid")
        except (ValueError, TypeError, PydanticSerializationError) as error:
            raise InvalidPlannedToolInputError(
                "Planned tool input does not satisfy its schema"
            ) from error
        steps.append(
            InvestigationStep(tool_name=step.tool_name, tool_input=canonical, purpose=step.purpose)
        )
    return InvestigationPlan(incident_id=incident_id, goal=validated.goal, steps=tuple(steps))
