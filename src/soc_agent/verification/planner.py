"""Plans observation only; no execution or authorization services."""

from uuid import UUID

from soc_agent.assessment import ThreatAssessment
from soc_agent.llm import LLMClient
from soc_agent.response import ResponsePlan
from soc_agent.state import IncidentState
from soc_agent.tools import ToolRegistry
from soc_agent.verification.errors import VerificationPlanningError
from soc_agent.verification.models import VerificationPlan, VerificationPlanDraft
from soc_agent.verification.prompts import build_planner_request
from soc_agent.verification.validator import normalize_plan, validate_target


class VerificationPlanner:
    def __init__(self, *, llm_client: LLMClient, registry: ToolRegistry) -> None:
        self._llm = llm_client
        self._registry = registry

    async def create_plan(
        self,
        *,
        incident_state: IncidentState,
        threat_assessment: ThreatAssessment,
        response_plan: ResponsePlan,
        response_step_id: UUID,
    ) -> VerificationPlan:
        state, assessment, response = validate_target(
            incident_state,
            threat_assessment,
            response_plan,
            response_step_id,
        )
        tools = {
            m.name: self._registry.get(m.name)
            for m in self._registry.list()
            if m.is_read_only_capability
        }
        if not tools:
            raise VerificationPlanningError("No observation-only verification tools registered")
        draft = await self._llm.generate_structured(
            request=build_planner_request(state, assessment, response, response_step_id, tools),
            response_model=VerificationPlanDraft,
        )
        return normalize_plan(
            draft,
            state=state,
            assessment=assessment,
            response=response,
            response_step_id=response_step_id,
            tools=tools,
        )
