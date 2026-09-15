"""Evidence-only assessment, without execution or incident mutation."""

from soc_agent.assessment import ThreatAssessment
from soc_agent.llm import LLMClient
from soc_agent.response import ResponsePlan
from soc_agent.state import IncidentState
from soc_agent.verification.errors import NoVerificationEvidenceError
from soc_agent.verification.models import (
    VerificationAssessment,
    VerificationAssessmentDraft,
    VerificationPlan,
)
from soc_agent.verification.prompts import build_assessment_request
from soc_agent.verification.validator import (
    convert_assessment,
    validate_collection,
    validate_target,
)


class VerificationAssessor:
    def __init__(self, *, llm_client: LLMClient) -> None:
        self._llm = llm_client

    async def assess(
        self,
        *,
        incident_state: IncidentState,
        threat_assessment: ThreatAssessment,
        response_plan: ResponsePlan,
        plan: VerificationPlan,
    ) -> VerificationAssessment:
        collection = validate_collection(incident_state, plan, response_plan)
        state, assessment, _ = validate_target(
            collection.incident_state,
            threat_assessment,
            response_plan,
            collection.plan.response_step_id,
        )
        if not collection.plan.verification_evidence_ids:
            raise NoVerificationEvidenceError("No post-action verification evidence")
        draft = await self._llm.generate_structured(
            request=build_assessment_request(collection, assessment),
            response_model=VerificationAssessmentDraft,
        )
        return convert_assessment(draft, collection)
