from uuid import uuid4

import pytest
from pydantic import JsonValue

from soc_agent.investigation import InvestigationStepStatus
from soc_agent.planning import (
    InvalidPlannedToolInputError,
    LLMInvestigationPlanDraft,
    UnknownPlannedToolError,
)
from soc_agent.planning.validator import normalize_plan
from soc_agent.tools import MockTool, ToolRegistry


def test_normalization_and_generated_ids(
    response: dict[str, JsonValue], registry: ToolRegistry, mock_tool: MockTool
) -> None:
    draft = LLMInvestigationPlanDraft.model_validate(response)
    incident_id = uuid4()
    tools = {m.name: registry.get(m.name) for m in registry.list()}
    first = normalize_plan(draft, incident_id=incident_id, tools=tools)
    second = normalize_plan(draft, incident_id=incident_id, tools=tools)
    assert first.incident_id == second.incident_id == incident_id
    assert first.goal == draft.goal
    assert first.plan_id != second.plan_id
    assert first.steps[0].step_id != second.steps[0].step_id
    assert first.steps[0].action_id != second.steps[0].action_id
    assert first.steps[0].status is InvestigationStepStatus.PENDING
    assert first.steps[0].tool_input == '{"limit":10,"username":"alice"}'
    assert mock_tool.call_count == 0


@pytest.mark.parametrize(
    "payload", [{"ip": 123}, {"username": 123}, {"username": "alice", "extra": True}]
)
def test_invalid_input(
    response: dict[str, JsonValue], registry: ToolRegistry, payload: dict[str, object]
) -> None:
    draft = LLMInvestigationPlanDraft.model_validate(
        response | {"steps": [response["steps"][0] | {"tool_input": payload}]}
    )
    with pytest.raises(InvalidPlannedToolInputError) as caught:
        normalize_plan(
            draft,
            incident_id=uuid4(),
            tools={m.name: registry.get(m.name) for m in registry.list()},
        )
    assert caught.value.__cause__ is not None


def test_unknown_tool(response: dict[str, JsonValue]) -> None:
    draft = LLMInvestigationPlanDraft.model_validate(response)
    with pytest.raises(UnknownPlannedToolError):
        normalize_plan(draft, incident_id=uuid4(), tools={})


def test_duplicates_preserved_with_distinct_ids(
    response: dict[str, JsonValue], registry: ToolRegistry
) -> None:
    draft = LLMInvestigationPlanDraft.model_validate(response | {"steps": response["steps"] * 2})
    plan = normalize_plan(
        draft, incident_id=uuid4(), tools={m.name: registry.get(m.name) for m in registry.list()}
    )
    assert len(plan.steps) == 2
    assert plan.steps[0].action_id != plan.steps[1].action_id
