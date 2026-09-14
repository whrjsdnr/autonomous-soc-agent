"""Planning proposes; governed execution independently decides eligibility."""

import pytest
from pydantic import BaseModel, JsonValue

from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.investigation import InvestigationOrchestrator, InvestigationStepStatus
from soc_agent.llm import MockLLMClient
from soc_agent.planning import InvestigationPlanner
from soc_agent.policy import PolicyEngine
from soc_agent.state import IncidentState
from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class Query(BaseModel):
    username: str


class Records(BaseModel):
    records: list[str]


@pytest.mark.parametrize(
    "risk", [ToolRiskLevel.READ_ONLY, ToolRiskLevel.HIGH, ToolRiskLevel.DESTRUCTIVE]
)
@pytest.mark.asyncio
async def test_llm_planned_investigation(risk: ToolRiskLevel) -> None:
    state = IncidentState()
    registry = ToolRegistry()
    names = ["search_auth_logs", "search_ip_activity", "get_host_sessions"]
    mocks = []
    for name in names:
        mock = MockTool(
            metadata=ToolMetadata(
                name=name,
                description="Fixture security data",
                permission=ToolPermission.SYSTEM_READ
                if risk == ToolRiskLevel.READ_ONLY
                else ToolPermission.SYSTEM_WRITE,
                risk_level=risk,
            ),
            input_model=Query,
            output_model=Records,
            responses=[{"records": [f"{name}: alice fixture"]}],
        )
        registry.register(mock.tool)
        mocks.append(mock)
    steps: list[JsonValue] = [
        {
            "tool_name": name,
            "tool_input": {"username": "alice"},
            "purpose": "Investigate suspicious authentication activity",
        }
        for name in names
    ]
    llm = MockLLMClient(
        [{"goal": "Investigate suspicious authentication activity for alice", "steps": steps}]
    )
    planner = InvestigationPlanner(llm_client=llm, registry=registry)
    plan = await planner.create_plan(state)
    assert llm.call_count == 1
    assert len(plan.steps) == 3
    assert [mock.call_count for mock in mocks] == [0, 0, 0]
    executor = GovernedExecutor(
        registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    result = await InvestigationOrchestrator(executor=executor).execute_plan(
        incident_state=state, plan=plan
    )
    if risk == ToolRiskLevel.READ_ONLY:
        assert [mock.call_count for mock in mocks] == [1, 1, 1]
        assert len(result.incident_state.evidence) == 3
        assert all(step.status is InvestigationStepStatus.COMPLETED for step in result.plan.steps)
    else:
        assert [mock.call_count for mock in mocks] == [0, 0, 0]
        assert result.incident_state.evidence == ()
        assert result.plan.steps[0].status is InvestigationStepStatus.BLOCKED
        assert result.plan.steps[0].failure.error_type == (
            "ApprovalRequiredError" if risk == ToolRiskLevel.HIGH else "ExecutionDeniedError"
        )
    assert result.incident_state.severity == state.severity
    assert result.incident_state.observations == result.incident_state.hypotheses == ()
