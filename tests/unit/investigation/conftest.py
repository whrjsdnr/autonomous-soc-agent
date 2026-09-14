from collections.abc import Sequence

import pytest
from pydantic import BaseModel, ConfigDict, JsonValue

from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.investigation import InvestigationOrchestrator, InvestigationPlan, InvestigationStep
from soc_agent.policy import PolicyEngine
from soc_agent.state import IncidentState
from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class Query(BaseModel):
    model_config = ConfigDict(strict=True)
    user: str


class Records(BaseModel):
    count: int


@pytest.fixture
def state() -> IncidentState:
    return IncidentState()


@pytest.fixture
def plan(state: IncidentState) -> InvestigationPlan:
    return InvestigationPlan(
        incident_id=state.incident_id,
        steps=(
            InvestigationStep(
                tool_name="log_search",
                tool_input={"user": "alice"},
                purpose="Inspect login failures",
            ),
        ),
    )


@pytest.fixture
def registry() -> ToolRegistry:
    return ToolRegistry()


@pytest.fixture
def approvals() -> ApprovalManager:
    return ApprovalManager()


@pytest.fixture
def executor(registry: ToolRegistry, approvals: ApprovalManager) -> GovernedExecutor:
    return GovernedExecutor(registry=registry, approvals=approvals, policy=PolicyEngine())


@pytest.fixture
def orchestrator(executor: GovernedExecutor) -> InvestigationOrchestrator:
    return InvestigationOrchestrator(executor=executor)


def make_mock(
    risk: ToolRiskLevel = ToolRiskLevel.READ_ONLY,
    name: str = "log_search",
    responses: Sequence[JsonValue | Exception] | None = None,
) -> MockTool[Query, Records]:
    return MockTool(
        metadata=ToolMetadata(
            name=name, description="Fixture", permission=ToolPermission.FILE_READ, risk_level=risk
        ),
        input_model=Query,
        output_model=Records,
        responses=responses if responses is not None else [{"count": 327}],
    )
