from datetime import UTC, datetime

import pytest
from pydantic import JsonValue

from soc_agent.state import Evidence, IncidentState


@pytest.fixture
def state() -> IncidentState:
    state = IncidentState()
    for summary in ("43 failed logins in 10 minutes", "One source tried 7 accounts"):
        state = state.add_evidence(
            Evidence(
                incident_id=state.incident_id,
                source="auth.log",
                summary=summary,
                raw_data=summary,
                observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        )
    return state


@pytest.fixture
def response(state: IncidentState) -> dict[str, JsonValue]:
    ids = [str(e.evidence_id) for e in state.evidence]
    return {
        "observations": [
            {
                "ref": "O1",
                "statement": "Repeated authentication failures occurred.",
                "supporting_evidence_ids": [ids[0]],
            }
        ],
        "hypotheses": [
            {
                "ref": "H1",
                "statement": "Possible password spraying.",
                "supporting_evidence_ids": ids,
                "confidence": 0.82,
            }
        ],
        "assessment": {
            "severity": "high",
            "confidence": 0.84,
            "summary": "Activity may indicate password spraying.",
            "supporting_evidence_ids": ids,
            "supporting_observation_refs": ["O1"],
            "supporting_hypothesis_refs": ["H1"],
        },
    }
