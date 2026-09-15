"""Revalidation rejects modified drafts before creating an executable plan."""

import pytest

from soc_agent.response import ResponsePlanDraft, ResponsePlanningError
from soc_agent.response.validator import normalize_plan


def test_mutated_draft_is_revalidated(context, payload, setup_tools):
    draft = ResponsePlanDraft.model_validate(payload)
    draft.steps[0].tool_input["ip"] = 123
    mock, *_ = setup_tools()
    with pytest.raises(ResponsePlanningError):
        normalize_plan(
            draft,
            incident_id=context[0].incident_id,
            assessment_id=context[1].assessment_id,
            tools={"block_ip": mock.tool},
        )
    assert mock.call_count == 0


def test_schema_defaults_and_aliases_are_bound_before_approval(context, payload) -> None:
    from pydantic import BaseModel, Field

    from soc_agent.execution import ActionProposal
    from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRiskLevel

    class Input(BaseModel):
        ip: str
        duration_minutes: int = Field(default=10, alias="duration")

    class Output(BaseModel):
        accepted: bool

    mock = MockTool(
        metadata=ToolMetadata(
            name="block_ip",
            description="Temporary scoped block fixture",
            permission=ToolPermission.NETWORK_WRITE,
            risk_level=ToolRiskLevel.HIGH,
        ),
        input_model=Input,
        output_model=Output,
        responses=[],
    )
    plan = normalize_plan(
        ResponsePlanDraft.model_validate(payload),
        incident_id=context[0].incident_id,
        assessment_id=context[1].assessment_id,
        tools={"block_ip": mock.tool},
    )
    assert plan.steps[0].tool_input == ActionProposal.canonical_input(
        {"ip": "203.0.113.20", "duration": 10}
    )
    assert mock.call_count == 0
