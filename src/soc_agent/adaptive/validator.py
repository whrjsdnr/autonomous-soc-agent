"""Reuse existing plan conversions; forbid repeated investigation inputs."""

from collections.abc import Mapping

from pydantic import BaseModel, ValidationError

from soc_agent.adaptive.errors import AdaptivePlanningError, RepeatedInvestigationError
from soc_agent.adaptive.models import (
    AdaptiveDecisionType,
    AdaptiveInvestigationDecision,
    InvestigationContext,
    ReplanningDraft,
)
from soc_agent.llm import LLMResponseValidationError
from soc_agent.planning.models import LLMInvestigationPlanDraft
from soc_agent.planning.validator import normalize_plan
from soc_agent.security_ai import SecurityAI, SecurityAISelectionDraft
from soc_agent.security_ai.selection_validator import normalize_selection
from soc_agent.tools import Tool


def convert_decision(
    draft: ReplanningDraft,
    *,
    context: InvestigationContext,
    tools: Mapping[str, Tool[BaseModel, BaseModel]],
    models: Mapping[str, SecurityAI[BaseModel]],
) -> AdaptiveInvestigationDecision:
    try:
        draft = ReplanningDraft.model_validate(draft.model_dump(warnings=False))
    except ValidationError as error:
        raise LLMResponseValidationError("Invalid replanning draft") from error
    incident_id = context.incident.incident_id
    tool_plan = None
    ai_plan = None
    if draft.tool is not None:
        # Apply the same domain capability predicate even for direct converter callers.
        eligible = {
            name: tool for name, tool in tools.items() if tool.metadata.is_read_only_capability
        }
        tool_plan = normalize_plan(
            LLMInvestigationPlanDraft(goal=draft.reason, steps=(draft.tool,)),
            incident_id=incident_id,
            tools=eligible,
        )
        tool_step = tool_plan.steps[0]
        if any(
            (prior.tool_name, prior.tool_input) == (tool_step.tool_name, tool_step.tool_input)
            for plan in context.tool_history
            for prior in plan.steps
        ):
            raise RepeatedInvestigationError("Tool and canonical input already appear in history")
    if draft.ai is not None:
        ai_plan = normalize_selection(
            SecurityAISelectionDraft(
                decision="run_ai",
                goal=draft.reason,
                reason=draft.reason,
                selections=(draft.ai,),
            ),
            incident_id=incident_id,
            models=models,
        )
        ai_step = ai_plan.steps[0]
        if any(
            (prior.selection.model_name, prior.selection.model_input)
            == (ai_step.model_name, ai_step.model_input)
            for history in context.ai_history
            for prior in history.steps
        ):
            raise RepeatedInvestigationError("Model and canonical input already appear in history")
    if (
        draft.decision == AdaptiveDecisionType.READY_FOR_ASSESSMENT
        and not context.incident.evidence
    ):
        raise AdaptivePlanningError("Current ThreatAssessor requires observed evidence")
    return AdaptiveInvestigationDecision(
        incident_id=incident_id,
        decision=draft.decision,
        reason=draft.reason,
        budget=context.budget,
        next_tool_plan=tool_plan,
        next_ai_plan=ai_plan,
    )
