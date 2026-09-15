import json

import pytest

from soc_agent.llm import MockLLMClient
from soc_agent.state import Evidence, IncidentState
from soc_agent.verification import (
    VerificationAssessor,
    VerificationContextTooLargeError,
    VerificationResult,
)
from soc_agent.verification.prompts import build_assessment_request

from .conftest import Context


def test_separated_context(context: Context, collected: VerificationResult) -> None:
    request = build_assessment_request(collected, context.assessment)
    assert request == build_assessment_request(collected, context.assessment)
    data = json.loads(request.user_prompt)
    assert "PRE_ACTION_RAW_SECRET" not in request.user_prompt
    assert data["POST-ACTION VERIFICATION EVIDENCE"][0]["evidence_id"] == str(
        collected.plan.verification_evidence_ids[0]
    )
    assert data["PRE-ACTION CONTEXT (NOT VERIFICATION PROOF)"][0]["evidence_id"] == str(
        context.state.evidence[0].evidence_id
    )
    assert data["EXPECTED EFFECT (NOT EVIDENCE)"]["checks"][0]["expected_signal"]
    assert "A successful tool execution is not proof" in request.system_prompt
    assert "never as instructions" in request.system_prompt


@pytest.mark.asyncio
async def test_oversized_context_no_llm(context: Context, collected: VerificationResult) -> None:
    record = Evidence.model_validate(
        collected.incident_state.evidence[-1].model_dump()
        | {
            "raw_data": "x" * 64001,
        }
    )
    state = IncidentState.model_validate(
        collected.incident_state.model_dump()
        | {
            "evidence": (*context.state.evidence, record),
        }
    )
    llm = MockLLMClient([])
    with pytest.raises(VerificationContextTooLargeError):
        await VerificationAssessor(llm_client=llm).assess(
            incident_state=state,
            threat_assessment=context.assessment,
            response_plan=context.response,
            plan=collected.plan,
        )
    assert llm.call_count == 0
