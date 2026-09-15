from uuid import uuid4

import pytest

from soc_agent.llm import MockLLMClient
from soc_agent.verification import (
    InvalidVerificationEvidenceError,
    NoVerificationEvidenceError,
    VerificationAssessment,
    VerificationAssessor,
    VerificationOutcome,
    VerificationPlan,
    VerificationResult,
)

from .conftest import Context


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", list(VerificationOutcome))
async def test_outcomes(
    context: Context, collected: VerificationResult, outcome: VerificationOutcome
) -> None:
    llm = MockLLMClient(
        [
            {
                "outcome": outcome.value,
                "confidence": 0.95,
                "summary": "Fixture interpretation",
                "supporting_evidence_ids": [
                    str(e) for e in collected.plan.verification_evidence_ids
                ],
            }
        ]
    )
    before = collected.model_dump_json()
    result = await VerificationAssessor(llm_client=llm).assess(
        incident_state=collected.incident_state,
        threat_assessment=context.assessment,
        response_plan=context.response,
        plan=collected.plan,
    )
    assert result.outcome is outcome
    assert result.target_action_id == context.response.steps[0].action_id
    assert result.response_step_id == context.response.steps[0].step_id
    assert result.response_plan_id == context.response.plan_id
    assert result.verification_plan_id == collected.plan.verification_plan_id
    assert result.supporting_evidence_ids == collected.plan.verification_evidence_ids
    assert result.incident_id == context.state.incident_id
    assert result.assessment_id == context.assessment.assessment_id
    assert VerificationAssessment.model_validate_json(result.model_dump_json()) == result
    assert collected.model_dump_json() == before and llm.call_count == 1


@pytest.mark.asyncio
async def test_no_evidence_no_llm(context: Context, plan: VerificationPlan) -> None:
    llm = MockLLMClient([])
    with pytest.raises(NoVerificationEvidenceError):
        await VerificationAssessor(llm_client=llm).assess(
            incident_state=context.state,
            threat_assessment=context.assessment,
            response_plan=context.response,
            plan=plan,
        )
    assert llm.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["unknown", "pre_action", "mixed"])
async def test_invalid_references_atomic(
    context: Context, collected: VerificationResult, kind: str
) -> None:
    invalid_id = uuid4() if kind == "unknown" else context.state.evidence[0].evidence_id
    refs = [str(invalid_id)]
    if kind == "mixed":
        refs += [str(collected.plan.verification_evidence_ids[0])]
    llm = MockLLMClient(
        [
            {
                "outcome": "verified",
                "confidence": 1.0,
                "summary": "Forged conclusion",
                "supporting_evidence_ids": refs,
            }
        ]
    )
    before = collected.model_dump_json()
    with pytest.raises(InvalidVerificationEvidenceError):
        await VerificationAssessor(llm_client=llm).assess(
            incident_state=collected.incident_state,
            threat_assessment=context.assessment,
            response_plan=context.response,
            plan=collected.plan,
        )
    assert llm.call_count == 1 and collected.model_dump_json() == before
