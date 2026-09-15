"""Advisory response planning without execution or authorization dependencies."""

from soc_agent.assessment import ThreatAssessment
from soc_agent.llm import LLMClient
from soc_agent.response.errors import ResponsePlanningError
from soc_agent.response.models import ResponsePlan, ResponsePlanDraft
from soc_agent.response.prompts import build_response_request
from soc_agent.response.validator import normalize_plan, validate_assessment
from soc_agent.state import IncidentState
from soc_agent.tools import ToolRegistry


class ResponsePlanner:
    def __init__(self, *, llm_client: LLMClient, registry: ToolRegistry) -> None:
        self._llm = llm_client
        self._registry = registry

    async def create_plan(
        self, *, incident_state: IncidentState, threat_assessment: ThreatAssessment
    ) -> ResponsePlan:
        validated = validate_assessment(incident_state, threat_assessment)
        state, assessment = validated.incident_state, validated.threat_assessment
        # Snapshot the allowlist before awaiting the LLM. No registration or policy filtering.
        tools = {m.name: self._registry.get(m.name) for m in self._registry.list()}
        if not tools:
            raise ResponsePlanningError("Cannot propose response without registered tools")
        draft = await self._llm.generate_structured(
            request=build_response_request(state, assessment, tools),
            response_model=ResponsePlanDraft,
        )
        return normalize_plan(
            draft,
            incident_id=state.incident_id,
            assessment_id=assessment.assessment_id,
            tools=tools,
        )
