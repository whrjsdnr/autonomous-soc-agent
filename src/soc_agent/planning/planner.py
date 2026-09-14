"""One structured LLM request, followed by deterministic plan validation."""

from soc_agent.investigation import InvestigationPlan
from soc_agent.llm import LLMClient
from soc_agent.planning.errors import PlanningError
from soc_agent.planning.models import LLMInvestigationPlanDraft
from soc_agent.planning.prompts import build_planner_input, build_request
from soc_agent.planning.validator import normalize_plan
from soc_agent.state import IncidentState
from soc_agent.tools import ToolRegistry


class InvestigationPlanner:
    """Produces plans only; caller separately invokes the governed orchestrator.

    Registry/schema definitions are trusted setup. No hidden retries or deduplication.
    LLM errors propagate with their original boundary meaning.
    """

    def __init__(self, *, llm_client: LLMClient, registry: ToolRegistry) -> None:
        self._llm = llm_client
        self._registry = registry

    async def create_plan(self, incident_state: IncidentState) -> InvestigationPlan:
        tools = {
            metadata.name: self._registry.get(metadata.name) for metadata in self._registry.list()
        }
        if not tools:
            raise PlanningError("Cannot plan without registered tools")
        context = build_planner_input(incident_state, tools)
        draft = await self._llm.generate_structured(
            request=build_request(context), response_model=LLMInvestigationPlanDraft
        )
        return normalize_plan(draft, incident_id=context.incident_id, tools=tools)
