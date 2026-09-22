"""Advisory analysis with only an injected LLM client, never execution services."""

from pydantic import ValidationError

from soc_agent.assessment.errors import InvalidAssessmentDraftError, NoEvidenceError
from soc_agent.assessment.fusion import (
    FusionAnalysisDraft,
    FusionAssessmentResult,
    validate_assessment_fusion,
)
from soc_agent.assessment.models import AssessmentResult, SecurityAnalysisDraft
from soc_agent.assessment.prompts import build_analysis_request
from soc_agent.assessment.validator import convert_analysis
from soc_agent.llm import LLMClient
from soc_agent.security_ai.fusion.models import FusionResult
from soc_agent.state import IncidentState


class ThreatAssessor:
    def __init__(self, *, llm_client: LLMClient) -> None:
        self._llm = llm_client

    async def assess(
        self, incident_state: IncidentState, *, fusion_result: FusionResult | None = None
    ) -> AssessmentResult:
        """Single request; preserve LLM errors and never return partial analysis."""
        state = IncidentState.model_validate(incident_state.model_dump(warnings=False))
        if not state.evidence:
            raise NoEvidenceError("Cannot assess an incident without evidence")
        fusion = (
            validate_assessment_fusion(fusion_result, state) if fusion_result is not None else None
        )
        draft = await self._llm.generate_structured(
            request=build_analysis_request(state, fusion_result=fusion),
            response_model=FusionAnalysisDraft if fusion is not None else SecurityAnalysisDraft,
        )
        if fusion is not None:
            # Revalidate even a client returning model_construct/model_copy objects.
            try:
                draft = FusionAnalysisDraft.model_validate(draft.model_dump(warnings=False))
            except ValidationError as error:
                raise InvalidAssessmentDraftError("Invalid fusion-aware analysis draft") from error
        result = convert_analysis(draft, state)
        if fusion is None:
            return result
        return FusionAssessmentResult(
            incident_state=result.incident_state,
            threat_assessment=result.threat_assessment,
            model_derived_context=fusion,
        )
