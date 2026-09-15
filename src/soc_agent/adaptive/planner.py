"""One bounded replanning pass, with no execution services or hidden retry."""

from types import MappingProxyType

from soc_agent.adaptive.context import validate_context
from soc_agent.adaptive.models import (
    AdaptiveDecisionType,
    AdaptiveInvestigationDecision,
    InvestigationContext,
    ReplanningDraft,
)
from soc_agent.adaptive.prompts import build_replanning_request
from soc_agent.adaptive.validator import convert_decision
from soc_agent.llm import LLMClient
from soc_agent.security_ai import SecurityAIRegistry
from soc_agent.tools import ToolRegistry


class AdaptiveInvestigationPlanner:
    def __init__(
        self, *, llm_client: LLMClient, tool_registry: ToolRegistry, ai_registry: SecurityAIRegistry
    ) -> None:
        self._llm = llm_client
        self._tools = tool_registry
        self._models = ai_registry

    async def replan(self, context: InvestigationContext) -> AdaptiveInvestigationDecision:
        context, signals = validate_context(context)
        if context.budget.current_round >= context.budget.max_rounds:
            return AdaptiveInvestigationDecision(
                incident_id=context.incident.incident_id,
                decision=AdaptiveDecisionType.ESCALATE_TO_HUMAN,
                reason="Investigation budget exhausted",
                budget=context.budget,
            )
        tools = MappingProxyType(
            {
                metadata.name: self._tools.get(metadata.name)
                for metadata in self._tools.list()
                if metadata.is_read_only_capability
            }
        )
        models = MappingProxyType(
            {metadata.name: self._models.get(metadata.name) for metadata in self._models.list()}
        )
        draft = await self._llm.generate_structured(
            request=build_replanning_request(context, signals, tools, models),
            response_model=ReplanningDraft,
        )
        return convert_decision(draft, context=context, tools=tools, models=models)
