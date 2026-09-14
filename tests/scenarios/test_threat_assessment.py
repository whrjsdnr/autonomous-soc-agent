"""Known mock reasoning outcomes; these tests do not measure a real model's accuracy."""

from datetime import UTC, datetime
from inspect import signature

import pytest

from soc_agent.assessment import ThreatAssessor
from soc_agent.llm import MockLLMClient
from soc_agent.state import Evidence, IncidentState, Severity


@pytest.mark.parametrize("ambiguous", [False, True])
@pytest.mark.asyncio
async def test_authentication_assessment(ambiguous: bool) -> None:
    state = IncidentState()
    facts = (
        ["5 failed logins for one account", "Source is a corporate VPN IP"]
        if ambiguous
        else [
            "43 failed logins for alice in 10 minutes",
            "Same source tried 7 accounts",
            "No successful login from that IP",
        ]
    )
    for fact in facts:
        state = state.add_evidence(
            Evidence(
                incident_id=state.incident_id,
                source="auth.log",
                summary=fact,
                raw_data=fact,
                observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        )
    ids = [str(e.evidence_id) for e in state.evidence]
    observations = [
        {
            "ref": "O1",
            "statement": "Repeated authentication failures occurred.",
            "supporting_evidence_ids": [ids[0]],
        },
        {
            "ref": "O2",
            "statement": "Source is a corporate VPN IP."
            if ambiguous
            else "One source attempted authentication across multiple accounts.",
            "supporting_evidence_ids": [ids[1]],
        },
    ]
    hypothesis = (
        "Could be user error or suspicious authentication."
        if ambiguous
        else "This may be password spraying."
    )
    confidence = 0.3 if ambiguous else 0.84
    llm = MockLLMClient(
        [
            {
                "observations": observations,
                "hypotheses": [
                    {
                        "ref": "H1",
                        "statement": hypothesis,
                        "confidence": 0.3 if ambiguous else 0.86,
                        "supporting_evidence_ids": ids,
                    }
                ],
                "assessment": {
                    "severity": "low" if ambiguous else "high",
                    "confidence": confidence,
                    "summary": "Activity remains ambiguous."
                    if ambiguous
                    else "Authentication activity suggests a likely password spraying attempt.",
                    "supporting_evidence_ids": ids,
                    "supporting_observation_refs": ["O1", "O2"],
                    "supporting_hypothesis_refs": ["H1"],
                },
            }
        ]
    )
    assessor = ThreatAssessor(llm_client=llm)
    result = await assessor.assess(state)
    assert llm.call_count == 1
    assert len(result.incident_state.observations) == 2
    assert len(result.incident_state.hypotheses) == 1
    assert result.threat_assessment.severity is (Severity.LOW if ambiguous else Severity.HIGH)
    assert result.threat_assessment.confidence == confidence
    assert result.threat_assessment.supporting_evidence_ids == tuple(
        e.evidence_id for e in state.evidence
    )
    assert result.threat_assessment.supporting_observation_ids == tuple(
        o.observation_id for o in result.incident_state.observations
    )
    assert result.threat_assessment.supporting_hypothesis_ids == (
        result.incident_state.hypotheses[0].hypothesis_id,
    )
    assert state.observations == state.hypotheses == ()
    assert result.incident_state.evidence == state.evidence
    assert result.incident_state.severity == state.severity
    # No execution services can be injected; all runtime collaborators are the mock LLM.
    assert set(signature(ThreatAssessor).parameters) == {"llm_client"}
    assert list(vars(assessor).values()) == [llm]
