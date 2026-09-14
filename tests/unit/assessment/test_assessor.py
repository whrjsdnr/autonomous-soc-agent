from uuid import uuid4

import pytest
from pydantic import JsonValue

from soc_agent.assessment import (
    AssessmentContextTooLargeError,
    InvalidEvidenceReferenceError,
    NoEvidenceError,
    ThreatAssessor,
)
from soc_agent.llm import LLMResponseValidationError, MockLLMClient
from soc_agent.state import Evidence, IncidentState


@pytest.mark.asyncio
async def test_no_evidence_skips_llm() -> None:
    llm = MockLLMClient([])
    with pytest.raises(NoEvidenceError):
        await ThreatAssessor(llm_client=llm).assess(IncidentState())
    assert llm.call_count == 0


@pytest.mark.asyncio
async def test_success(state: IncidentState, response: dict[str, JsonValue]) -> None:
    llm = MockLLMClient([response])
    result = await ThreatAssessor(llm_client=llm).assess(state)
    assert llm.call_count == 1
    assert result.incident_state.observations[0].supporting_evidence_ids == (
        state.evidence[0].evidence_id,
    )
    assert result.incident_state.hypotheses[0].supporting_evidence_ids == tuple(
        e.evidence_id for e in state.evidence
    )
    assert state.observations == state.hypotheses == ()


@pytest.mark.parametrize("kind", ["schema", "reference"])
@pytest.mark.asyncio
async def test_invalid_analysis_no_retry(
    state: IncidentState, response: dict[str, JsonValue], kind: str
) -> None:
    if kind == "schema":
        response["assessment"]["confidence"] = 2
        error = LLMResponseValidationError
    else:
        response["assessment"]["supporting_evidence_ids"] = [str(uuid4())]
        error = InvalidEvidenceReferenceError
    llm = MockLLMClient([response, response])
    with pytest.raises(error):
        await ThreatAssessor(llm_client=llm).assess(state)
    assert llm.call_count == 1
    assert state.observations == state.hypotheses == ()


@pytest.mark.asyncio
async def test_oversized_context_skips_llm(state: IncidentState) -> None:
    item = Evidence.model_validate(state.evidence[0].model_dump() | {"summary": "x" * 64001})
    state = IncidentState(incident_id=state.incident_id, evidence=(item,))
    llm = MockLLMClient([])
    with pytest.raises(AssessmentContextTooLargeError):
        await ThreatAssessor(llm_client=llm).assess(state)
    assert llm.call_count == 0
