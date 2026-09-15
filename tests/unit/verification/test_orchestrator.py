from uuid import uuid4

import pytest

from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.policy import PolicyDecision, PolicyEngine, PolicyResult
from soc_agent.tools import ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel
from soc_agent.verification import (
    VerificationOrchestrator,
    VerificationPlan,
    VerificationResult,
    VerificationStep,
    VerificationStepStateError,
    VerificationStepStatus,
)

from .conftest import Context, Runtime, make_tool


@pytest.mark.asyncio
async def test_collection_and_replay(
    context: Context,
    runtime: Runtime,
    plan: VerificationPlan,
    collected: VerificationResult,
) -> None:
    step = plan.steps[0]
    action = runtime.orchestrator.prepare_step(
        incident_state=context.state,
        response_plan=context.response,
        plan=plan,
        step_id=step.step_id,
    )
    assert action.action_id == step.verification_action_id
    assert action.tool_input == step.tool_input
    assert collected.plan.steps[0].status is VerificationStepStatus.COMPLETED
    record = collected.incident_state.evidence[-1]
    assert record.evidence_id == collected.plan.steps[0].evidence_id
    assert record.tool_name == step.tool_name
    assert record.collected_at >= collected.plan.steps[0].started_at >= plan.created_at
    assert '"message":"No attempts after block"' in record.raw_data
    assert collected.incident_state.evidence[:-1] == context.state.evidence
    assert collected.incident_state.status == context.state.status
    assert collected.incident_state.severity == context.state.severity
    assert collected.incident_state.observations == context.state.observations
    assert collected.incident_state.hypotheses == context.state.hypotheses
    assert plan.steps[0].status is VerificationStepStatus.PENDING
    assert runtime.mock.call_count == 1
    with pytest.raises(VerificationStepStateError):
        await runtime.orchestrator.execute_step(
            incident_state=collected.incident_state,
            response_plan=context.response,
            plan=collected.plan,
            step_id=step.step_id,
        )
    replay = await runtime.orchestrator.execute_plan(
        incident_state=context.state,
        response_plan=context.response,
        plan=plan,
    )
    assert replay.plan.steps[0].status is VerificationStepStatus.BLOCKED
    assert replay.plan.steps[0].failure.error_type == "ActionAlreadyAttemptedError"
    assert runtime.mock.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["policy", "runtime", "write", "input", "output"])
async def test_stop_without_retry(context: Context, plan: VerificationPlan, kind: str) -> None:
    class DenyPolicy(PolicyEngine):
        def evaluate(self, metadata: ToolMetadata) -> PolicyResult:
            return PolicyResult(decision=PolicyDecision.DENY, reason="Fixture restriction")

    mock = make_tool(
        permission=ToolPermission.NETWORK_WRITE if kind == "write" else ToolPermission.NETWORK_READ,
        risk=ToolRiskLevel.LOW,
        responses=[RuntimeError("Backend unavailable")]
        if kind == "runtime"
        else [{}]
        if kind == "output"
        else [{"message": "ok"}],
    )
    registry = ToolRegistry()
    registry.register(mock.tool)
    second = VerificationStep.model_validate(
        plan.steps[0].model_dump()
        | {
            "step_id": uuid4(),
            "verification_action_id": uuid4(),
        }
    )
    first = plan.steps[0]
    if kind == "input":
        first = VerificationStep.model_validate(first.model_dump() | {"tool_input": {"ip": 123}})
    plan = VerificationPlan.model_validate(plan.model_dump() | {"steps": (first, second)})
    executor = GovernedExecutor(
        registry=registry,
        approvals=ApprovalManager(),
        policy=DenyPolicy() if kind == "policy" else PolicyEngine(),
    )
    orchestrator = VerificationOrchestrator(executor=executor)
    result = await orchestrator.execute_plan(
        incident_state=context.state,
        response_plan=context.response,
        plan=plan,
    )
    expected = (
        VerificationStepStatus.BLOCKED
        if kind in ("policy", "write")
        else VerificationStepStatus.FAILED
    )
    assert result.plan.steps[0].status is expected
    assert result.plan.steps[1].status is VerificationStepStatus.PENDING
    assert result.incident_state == context.state
    assert mock.call_count == (1 if kind in ("runtime", "output") else 0)
    again = await orchestrator.execute_plan(
        incident_state=result.incident_state,
        response_plan=context.response,
        plan=result.plan,
    )
    assert again == result
    assert mock.call_count == (1 if kind in ("runtime", "output") else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "permission,risk",
    [
        (ToolPermission.NETWORK_WRITE, ToolRiskLevel.LOW),
        (ToolPermission.NETWORK_WRITE, ToolRiskLevel.HIGH),
        (ToolPermission.NETWORK_READ, ToolRiskLevel.HIGH),
        (ToolPermission.FILE_WRITE, ToolRiskLevel.DESTRUCTIVE),
    ],
)
async def test_executor_observation_scope_beats_approval(
    context: Context,
    permission: ToolPermission,
    risk: ToolRiskLevel,
) -> None:
    from soc_agent.execution import ActionProposal, ExecutionDeniedError

    mock = make_tool(permission=permission, risk=risk)
    registry = ToolRegistry()
    registry.register(mock.tool)
    approvals = ApprovalManager()
    executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)
    action = ActionProposal(
        incident_id=context.state.incident_id,
        tool_name=mock.tool.metadata.name,
        tool_input={"ip": "x"},
    )
    request = approvals.create(
        incident_id=action.incident_id,
        metadata=mock.tool.metadata,
        reason="Cannot widen scope",
        action_id=action.action_id,
        action_input_json=action.tool_input,
    )
    approvals.approve(request.approval_id, actor="human")
    with pytest.raises(ExecutionDeniedError, match="observation-only"):
        await executor.execute(action, approval_id=request.approval_id, require_read_only=True)
    assert mock.call_count == 0


@pytest.mark.asyncio
async def test_sequential_order(context: Context, plan: VerificationPlan) -> None:
    import asyncio

    from soc_agent.tools import Tool

    from .conftest import Query, Record

    events: list[str] = []

    async def handler(query: Query) -> Record:
        events.append("start")
        await asyncio.sleep(0)
        events.append("end")
        return Record(message="Read completed")

    tool = Tool(make_tool().tool.metadata, Query, Record, handler)
    registry = ToolRegistry()
    registry.register(tool)
    second = VerificationStep.model_validate(
        plan.steps[0].model_dump()
        | {
            "step_id": uuid4(),
            "verification_action_id": uuid4(),
        }
    )
    plan = VerificationPlan.model_validate(plan.model_dump() | {"steps": (*plan.steps, second)})
    orchestrator = VerificationOrchestrator(
        executor=GovernedExecutor(
            registry=registry,
            policy=PolicyEngine(),
            approvals=ApprovalManager(),
        )
    )
    result = await orchestrator.execute_plan(
        incident_state=context.state,
        response_plan=context.response,
        plan=plan,
    )
    assert events == ["start", "end", "start", "end"]
    assert len(result.plan.verification_evidence_ids) == 2
