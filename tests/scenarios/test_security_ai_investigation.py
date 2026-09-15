"""Selection remains planning-only; execution separately produces analytical signals."""

import pytest
from pydantic import BaseModel, ConfigDict, Field

from soc_agent.llm import MockLLMClient
from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAIInvestigator,
    SecurityAIModelMetadata,
    SecurityAIRegistry,
    SecurityAISelector,
)
from soc_agent.state import Evidence, Hypothesis, IncidentState, Observation
from soc_agent.state.evidence import utc_now


class Features(BaseModel):
    model_config = ConfigDict(extra="forbid")
    failed_login_count: int = Field(ge=0)
    unique_accounts: int = Field(ge=1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario", ["single", "multiple", "version", "failure", "invalid_output", "noop"]
)
async def test_selector_to_investigation(scenario: str) -> None:
    state = IncidentState()
    for source in ("auth.log", "network.log"):
        state = state.add_evidence(
            Evidence(
                incident_id=state.incident_id,
                source=source,
                summary="43 failed logins against 7 accounts",
                raw_data="PRIVATE RAW RECORDS",
                observed_at=utc_now(),
            )
        )
    refs = tuple(item.evidence_id for item in state.evidence)
    state = state.add_observation(
        Observation(statement="43 failures recorded", supporting_evidence_ids=refs)
    )
    state = state.add_hypothesis(
        Hypothesis(
            statement="Possible credential abuse", confidence=0.4, supporting_evidence_ids=refs
        )
    )
    before = state.model_dump_json()
    registry = SecurityAIRegistry()
    mocks = []
    for index, name in enumerate(("auth_anomaly_mock", "network_anomaly_mock", "network_ids_mock")):
        response = {"prediction": "anomalous", "scores": {"anomaly_score": 0.87}}
        if scenario == "invalid_output" and index == 1:
            response = {"prediction": "", "scores": {}}
        mock = MockSecurityAI(
            metadata=SecurityAIModelMetadata(
                name=name,
                version="1.0",
                description="Fixture model",
                task_type="anomaly_detection",
                input_type="authentication_event",
            ),
            input_model=Features,
            responses=[
                RuntimeError("SECRET_FAILURE") if scenario == "failure" and index == 1 else response
            ],
        )
        registry.register(mock.model)
        mocks.append(mock)
    count = (
        0
        if scenario == "noop"
        else 3
        if scenario in {"failure", "invalid_output"}
        else 2
        if scenario == "multiple"
        else 1
    )
    client = MockLLMClient(
        [
            {
                "decision": "no_ai_needed" if scenario == "noop" else "run_ai",
                "goal": "Inspect logins",
                "reason": "Consider analytical input",
                "selections": [
                    {
                        "model_name": mock.model.metadata.name,
                        "model_input": {"failed_login_count": 43, "unique_accounts": 7},
                        "purpose": "Inspect authentication pattern",
                    }
                    for mock in mocks[:count]
                ],
            }
        ]
    )
    plan = await SecurityAISelector(llm_client=client, registry=registry).select(incident=state)
    assert client.call_count == 1 and all(mock.call_count == 0 for mock in mocks)
    plan_before = plan.model_dump_json()
    replacement = None
    if scenario == "version":
        registry = SecurityAIRegistry()
        replacement = MockSecurityAI(
            metadata=mocks[0].model.metadata.model_copy(update={"version": "2.0"}),
            input_model=Features,
            responses=[],
        )
        registry.register(replacement.model)
    result = await SecurityAIInvestigator(registry=registry).execute(
        incident=state,
        selection_plan=plan,
        source_evidence={step.step_id: refs for step in plan.steps},
    )
    statuses = [step.status.value for step in result.steps]
    if scenario == "version":
        assert statuses == ["blocked"] and replacement.call_count == 0
        assert result.results == result.signals == ()
    elif scenario in {"failure", "invalid_output"}:
        assert statuses == ["completed", "failed", "pending"]
        assert [mock.call_count for mock in mocks] == [1, 1, 0]
        assert len(result.results) == len(result.signals) == 1
        assert "SECRET_FAILURE" not in result.model_dump_json()
    else:
        assert statuses == ["completed"] * count
        assert sum(mock.call_count for mock in mocks) == count
        assert len(result.results) == len(result.signals) == count
    for raw, signal in zip(result.results, result.signals, strict=True):
        assert raw.result_id == signal.source_result_id
        assert raw.incident_id == signal.incident_id == state.incident_id
        assert raw.model_name == signal.model_name
        assert raw.model_version == signal.model_version == "1.0"
        assert signal.source_evidence_ids == refs
        assert signal.confidence is None and signal.scores_payload() == {"anomaly_score": 0.87}
        assert not isinstance(signal, (Evidence, Observation, Hypothesis))
    assert client.call_count == 1  # Execution did not ask the LLM again.
    assert state.model_dump_json() == before and plan.model_dump_json() == plan_before
