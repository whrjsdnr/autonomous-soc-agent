from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.approval import ApprovalManager, ApprovalRequest, ApprovalValidationError
from soc_agent.execution import ActionProposal, ApprovalBindingError, GovernedExecutor
from soc_agent.tools import MockTool, ToolPermission, ToolRegistry, ToolRiskLevel

from .conftest import make_tool


@pytest.mark.parametrize(
    "update",
    [
        {"action_id": uuid4()},
        {"incident_id": uuid4()},
        {"tool_input": {"target": "host_b"}},
        {"tool_name": "other_tool"},
    ],
)
@pytest.mark.asyncio
async def test_exact_binding_rejects_changes(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    high_tool: MockTool,
    registry: ToolRegistry,
    update: dict[str, object],
) -> None:
    other = make_tool(ToolPermission.NETWORK_WRITE, ToolRiskLevel.HIGH, "other_tool")
    registry.register(other.tool)
    request = executor.request_approval(action, reason="Review exact target")
    approvals.approve(request.approval_id, actor="human")
    changed = ActionProposal.model_validate(action.model_dump() | update)
    with pytest.raises(ApprovalBindingError):
        await executor.execute(changed, approval_id=request.approval_id)
    assert high_tool.call_count == other.call_count == 0


@pytest.mark.asyncio
async def test_unbound_legacy_approval_rejected(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    high_tool: MockTool,
) -> None:
    request = approvals.create(
        incident_id=action.incident_id, metadata=high_tool.tool.metadata, reason="Legacy"
    )
    approvals.approve(request.approval_id, actor="human")
    with pytest.raises(ApprovalBindingError):
        await executor.execute(action, approval_id=request.approval_id)
    assert high_tool.call_count == 0


@pytest.mark.parametrize("update", [{"action_id": uuid4()}, {"action_input_json": "{}"}])
def test_partial_binding_rejected(
    action: ActionProposal,
    high_tool: MockTool,
    approvals: ApprovalManager,
    update: dict[str, object],
) -> None:
    with pytest.raises(ApprovalValidationError):
        approvals.create(
            incident_id=action.incident_id,
            metadata=high_tool.tool.metadata,
            reason="Review",
            **update,
        )
    assert approvals.list() == ()


def test_binding_survives_decision_and_serialization(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    high_tool: MockTool,
) -> None:
    request = executor.request_approval(action, reason="Review")
    approved = approvals.approve(request.approval_id, actor="human")
    assert approved.action_id == action.action_id
    assert approved.action_input_json == action.tool_input
    assert ApprovalRequest.model_validate_json(approved.model_dump_json()) == approved
    with pytest.raises(ValidationError):
        approved.action_input_json = "{}"


@pytest.mark.parametrize(
    "update",
    [
        {"permission": ToolPermission.SYSTEM_WRITE},
        {"risk_level": ToolRiskLevel.MEDIUM},
    ],
)
@pytest.mark.asyncio
async def test_metadata_mismatch_rejected(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    high_tool: MockTool,
    update: dict[str, object],
) -> None:
    metadata = type(high_tool.tool.metadata).model_validate(
        high_tool.tool.metadata.model_dump() | update
    )
    request = approvals.create(
        incident_id=action.incident_id,
        metadata=metadata,
        reason="Different metadata",
        action_id=action.action_id,
        action_input_json=action.tool_input,
    )
    approvals.approve(request.approval_id, actor="human")
    with pytest.raises(ApprovalBindingError):
        await executor.execute(action, approval_id=request.approval_id)
    assert high_tool.call_count == 0
