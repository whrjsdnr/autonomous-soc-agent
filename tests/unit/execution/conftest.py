from uuid import uuid4

import pytest
from pydantic import BaseModel, ConfigDict

from soc_agent.approval import ApprovalManager
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.policy import PolicyEngine
from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class SampleInput(BaseModel):
    model_config = ConfigDict(strict=True)
    target: str


class SampleOutput(BaseModel):
    result: str


@pytest.fixture
def registry() -> ToolRegistry:
    return ToolRegistry()


@pytest.fixture
def approvals() -> ApprovalManager:
    return ApprovalManager()


@pytest.fixture
def executor(registry: ToolRegistry, approvals: ApprovalManager) -> GovernedExecutor:
    return GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)


@pytest.fixture
def high_tool(registry: ToolRegistry) -> MockTool[SampleInput, SampleOutput]:
    mock = make_tool(ToolPermission.NETWORK_WRITE, ToolRiskLevel.HIGH)
    registry.register(mock.tool)
    return mock


def make_tool(
    permission: ToolPermission, risk: ToolRiskLevel, name: str = "test_tool"
) -> MockTool[SampleInput, SampleOutput]:
    return MockTool(
        metadata=ToolMetadata(
            name=name, description="Fixture only", permission=permission, risk_level=risk
        ),
        input_model=SampleInput,
        output_model=SampleOutput,
        responses=[{"result": "ok"}, {"result": "ok"}],
    )


@pytest.fixture
def action() -> ActionProposal:
    return ActionProposal(
        incident_id=uuid4(), tool_name="test_tool", tool_input={"target": "host_a"}
    )
