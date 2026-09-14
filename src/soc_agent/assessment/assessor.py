"""Advisory analysis with only an injected LLM client, never execution services."""

from soc_agent.assessment.errors import NoEvidenceError
from soc_agent.assessment.models import AssessmentResult, SecurityAnalysisDraft
from soc_agent.assessment.prompts import build_analysis_request
from soc_agent.assessment.validator import convert_analysis
from soc_agent.llm import LLMClient
from soc_agent.state import IncidentState


class ThreatAssessor:
    def __init__(self, *, llm_client: LLMClient) -> None:
        self._llm = llm_client

    async def assess(self, incident_state: IncidentState) -> AssessmentResult:
        """Single request; preserve LLM errors and never return partial analysis."""
        state = IncidentState.model_validate(incident_state.model_dump(warnings=False))
        if not state.evidence:
            raise NoEvidenceError("Cannot assess an incident without evidence")
        draft = await self._llm.generate_structured(
            request=build_analysis_request(state), response_model=SecurityAnalysisDraft
        )
        return convert_analysis(draft, state)
