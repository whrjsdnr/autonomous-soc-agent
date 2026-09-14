import asyncio
from uuid import uuid4

import pytest

from soc_agent.approval import ApprovalManager, ApprovalNotFoundError
from soc_agent.execution import (
    ActionAlreadyAttemptedError,
    ActionProposal,
    ApprovalRejectedError,
    ApprovalRequiredError,
    ExecutionDeniedError,
    GovernedExecutor,
)
from soc_agent.tools import (
    MockTool,
    ToolExecutionError,
    ToolInputValidationError,
    ToolNotFoundError,
    ToolPermission,
    ToolRegistry,
    ToolRiskLevel,
)

from .conftest import SampleInput, SampleOutput, make_tool


@pytest.mark.parametrize("risk", [ToolRiskLevel.READ_ONLY, ToolRiskLevel.LOW])
@pytest.mark.asyncio
async def test_read_allowed(
    action: ActionProposal,
    executor: GovernedExecutor,
    registry: ToolRegistry,
    approvals: ApprovalManager,
    risk: ToolRiskLevel,
) -> None:
    mock = make_tool(ToolPermission.FILE_READ, risk)
    registry.register(mock.tool)
    result = await executor.execute(action)
    assert result.output.result == "ok"
    assert mock.call_count == 1
    assert approvals.list() == ()


@pytest.mark.parametrize("risk", [ToolRiskLevel.LOW, ToolRiskLevel.MEDIUM, ToolRiskLevel.HIGH])
@pytest.mark.asyncio
async def test_write_requires_approval(
    action: ActionProposal,
    executor: GovernedExecutor,
    registry: ToolRegistry,
    approvals: ApprovalManager,
    risk: ToolRiskLevel,
) -> None:
    mock = make_tool(ToolPermission.NETWORK_WRITE, risk)
    registry.register(mock.tool)
    with pytest.raises(ApprovalRequiredError):
        await executor.execute(action)
    assert mock.call_count == 0
    assert approvals.list() == ()


@pytest.mark.parametrize(
    "status,error", [("pending", ApprovalRequiredError), ("rejected", ApprovalRejectedError)]
)
@pytest.mark.asyncio
async def test_unapproved_never_executes(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    high_tool: MockTool,
    status: str,
    error: type[Exception],
) -> None:
    request = executor.request_approval(action, reason="Review")
    if status == "rejected":
        approvals.reject(request.approval_id, actor="human")
    with pytest.raises(error):
        await executor.execute(action, approval_id=request.approval_id)
    assert high_tool.call_count == 0


@pytest.mark.asyncio
async def test_approved_executes_once_even_concurrently(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    high_tool: MockTool,
) -> None:
    request = executor.request_approval(action, reason="Review")
    approvals.approve(request.approval_id, actor="human")
    results = await asyncio.gather(
        executor.execute(action, approval_id=request.approval_id),
        executor.execute(action, approval_id=request.approval_id),
        return_exceptions=True,
    )
    assert sum(isinstance(result, ActionAlreadyAttemptedError) for result in results) == 1
    assert high_tool.call_count == 1
    with pytest.raises(ActionAlreadyAttemptedError):
        await executor.execute(action, approval_id=request.approval_id)


@pytest.mark.asyncio
async def test_deny_overrides_approved_record(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    registry: ToolRegistry,
) -> None:
    mock = make_tool(ToolPermission.FILE_WRITE, ToolRiskLevel.DESTRUCTIVE)
    registry.register(mock.tool)
    request = approvals.create(
        incident_id=action.incident_id,
        metadata=mock.tool.metadata,
        reason="Artificial approval",
        action_id=action.action_id,
        action_input_json=action.tool_input,
    )
    approvals.approve(request.approval_id, actor="human")
    with pytest.raises(ExecutionDeniedError):
        await executor.execute(action, approval_id=request.approval_id)
    with pytest.raises(ExecutionDeniedError):
        executor.request_approval(action, reason="Cannot override deny")
    assert mock.call_count == 0


@pytest.mark.asyncio
async def test_unknown_tool_and_approval(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    high_tool: MockTool,
) -> None:
    request = executor.request_approval(action, reason="Review")
    approvals.approve(request.approval_id, actor="human")
    unknown = ActionProposal.model_validate(action.model_dump() | {"tool_name": "run_shell"})
    with pytest.raises(ToolNotFoundError):
        await executor.execute(unknown, approval_id=request.approval_id)
    with pytest.raises(ApprovalNotFoundError):
        await executor.execute(action, approval_id=uuid4())
    assert high_tool.call_count == 0


@pytest.mark.parametrize("payload", [{}, {"target": 42}, {"target": "host_a", "extra": True}])
@pytest.mark.parametrize("approved", [False, True])
@pytest.mark.asyncio
async def test_input_validation_cannot_be_bypassed(
    action: ActionProposal,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
    registry: ToolRegistry,
    payload: dict[str, object],
    approved: bool,
) -> None:
    mock = make_tool(
        ToolPermission.NETWORK_WRITE if approved else ToolPermission.FILE_READ,
        ToolRiskLevel.HIGH if approved else ToolRiskLevel.READ_ONLY,
    )
    registry.register(mock.tool)
    invalid = ActionProposal.model_validate(action.model_dump() | {"tool_input": payload})
    approval_id = None
    if approved:
        request = executor.request_approval(invalid, reason="Even approved input must validate")
        approvals.approve(request.approval_id, actor="human")
        approval_id = request.approval_id
    with pytest.raises(ToolInputValidationError):
        await executor.execute(invalid, approval_id=approval_id)
    assert mock.call_count == 0


@pytest.mark.asyncio
async def test_failure_preserved_without_retry(
    action: ActionProposal, executor: GovernedExecutor, registry: ToolRegistry
) -> None:
    metadata = make_tool(ToolPermission.FILE_READ, ToolRiskLevel.READ_ONLY).tool.metadata
    mock = MockTool(
        metadata=metadata,
        input_model=SampleInput,
        output_model=SampleOutput,
        responses=[ToolExecutionError("Fixture failure"), {"result": "ok"}],
    )
    registry.register(mock.tool)
    with pytest.raises(ToolExecutionError, match="Fixture failure"):
        await executor.execute(action)
    with pytest.raises(ActionAlreadyAttemptedError):
        await executor.execute(action)
    assert mock.call_count == 1
