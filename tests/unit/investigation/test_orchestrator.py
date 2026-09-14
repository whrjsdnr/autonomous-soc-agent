from uuid import uuid4

import pytest

from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.investigation import (
    InvestigationOrchestrator,
    InvestigationPlan,
    InvestigationPlanMismatchError,
    InvestigationStep,
    InvestigationStepNotFoundError,
    InvestigationStepStateError,
    InvestigationStepStatus,
)
from soc_agent.state import IncidentState
from soc_agent.tools import ToolExecutionError, ToolRegistry, ToolRiskLevel

from .conftest import make_mock


@pytest.mark.asyncio
async def test_success(
    state: IncidentState,
    plan: InvestigationPlan,
    registry: ToolRegistry,
    orchestrator: InvestigationOrchestrator,
) -> None:
    mock = make_mock()
    registry.register(mock.tool)
    result = await orchestrator.execute_step(
        incident_state=state, plan=plan, step_id=plan.steps[0].step_id
    )
    assert mock.call_count == 1
    assert len(result.incident_state.evidence) == 1
    step = result.plan.steps[0]
    assert step.status is InvestigationStepStatus.COMPLETED
    assert step.evidence_id == result.incident_state.evidence[0].evidence_id
    assert step.action_id == plan.steps[0].action_id
    assert state.evidence == ()
    assert result.incident_state.observations == result.incident_state.hypotheses == ()
    assert result.incident_state.severity == state.severity
    with pytest.raises(InvestigationStepStateError):
        await orchestrator.execute_step(
            incident_state=result.incident_state, plan=result.plan, step_id=step.step_id
        )
    assert mock.call_count == 1


@pytest.mark.parametrize(
    "risk,error_type",
    [
        (ToolRiskLevel.HIGH, "ApprovalRequiredError"),
        (ToolRiskLevel.DESTRUCTIVE, "ExecutionDeniedError"),
    ],
)
@pytest.mark.asyncio
async def test_governance_block(
    state: IncidentState,
    plan: InvestigationPlan,
    registry: ToolRegistry,
    orchestrator: InvestigationOrchestrator,
    risk: ToolRiskLevel,
    error_type: str,
) -> None:
    mock = make_mock(risk)
    registry.register(mock.tool)
    result = await orchestrator.execute_step(
        incident_state=state, plan=plan, step_id=plan.steps[0].step_id
    )
    assert result.plan.steps[0].status is InvestigationStepStatus.BLOCKED
    assert result.plan.steps[0].failure.error_type == error_type
    assert result.incident_state == state
    assert mock.call_count == 0


@pytest.mark.asyncio
async def test_stable_approval_and_explicit_resume(
    state: IncidentState,
    plan: InvestigationPlan,
    registry: ToolRegistry,
    orchestrator: InvestigationOrchestrator,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
) -> None:
    mock = make_mock(ToolRiskLevel.HIGH)
    registry.register(mock.tool)
    step_id = plan.steps[0].step_id
    prepared = orchestrator.prepare_step(incident_state=state, plan=plan, step_id=step_id)
    request = executor.request_approval(prepared, reason="Review")
    blocked = await orchestrator.execute_step(
        incident_state=state, plan=plan, step_id=step_id, approval_id=request.approval_id
    )
    assert blocked.plan.steps[0].status is InvestigationStepStatus.BLOCKED
    assert prepared == orchestrator.prepare_step(
        incident_state=state, plan=blocked.plan, step_id=step_id
    )
    approvals.approve(request.approval_id, actor="operator")
    result = await orchestrator.execute_step(
        incident_state=state, plan=blocked.plan, step_id=step_id, approval_id=request.approval_id
    )
    assert result.plan.steps[0].status is InvestigationStepStatus.COMPLETED
    assert mock.call_count == 1


@pytest.mark.asyncio
async def test_wrong_approval(
    state: IncidentState,
    plan: InvestigationPlan,
    registry: ToolRegistry,
    orchestrator: InvestigationOrchestrator,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
) -> None:
    mock = make_mock(ToolRiskLevel.HIGH)
    registry.register(mock.tool)
    other_plan = InvestigationPlan(
        incident_id=state.incident_id,
        steps=(
            InvestigationStep(
                tool_name="log_search", tool_input={"user": "bob"}, purpose="Inspect"
            ),
        ),
    )
    other = orchestrator.prepare_step(
        incident_state=state, plan=other_plan, step_id=other_plan.steps[0].step_id
    )
    request = executor.request_approval(other, reason="Review")
    approvals.approve(request.approval_id, actor="operator")
    result = await orchestrator.execute_step(
        incident_state=state,
        plan=plan,
        step_id=plan.steps[0].step_id,
        approval_id=request.approval_id,
    )
    assert result.plan.steps[0].failure.error_type == "ApprovalBindingError"
    assert result.plan.steps[0].status is InvestigationStepStatus.BLOCKED
    assert result.incident_state == state
    assert mock.call_count == 0


@pytest.mark.asyncio
async def test_deny_even_with_approval(
    state: IncidentState,
    plan: InvestigationPlan,
    registry: ToolRegistry,
    orchestrator: InvestigationOrchestrator,
    executor: GovernedExecutor,
    approvals: ApprovalManager,
) -> None:
    mock = make_mock(ToolRiskLevel.DESTRUCTIVE)
    registry.register(mock.tool)
    action = orchestrator.prepare_step(
        incident_state=state, plan=plan, step_id=plan.steps[0].step_id
    )
    request = approvals.create(
        incident_id=state.incident_id,
        metadata=mock.tool.metadata,
        reason="Artificial",
        action_id=action.action_id,
        action_input_json=action.tool_input,
    )
    approvals.approve(request.approval_id, actor="operator")
    result = await orchestrator.execute_step(
        incident_state=state,
        plan=plan,
        step_id=plan.steps[0].step_id,
        approval_id=request.approval_id,
    )
    assert result.plan.steps[0].failure.error_type == "ExecutionDeniedError"
    assert result.incident_state == state
    assert mock.call_count == 0


@pytest.mark.parametrize(
    "kind,expected,calls",
    [
        ("runtime", "ToolExecutionError", 1),
        ("input", "ToolInputValidationError", 0),
        ("output", "ToolOutputValidationError", 1),
    ],
)
@pytest.mark.asyncio
async def test_failures(
    state: IncidentState,
    plan: InvestigationPlan,
    registry: ToolRegistry,
    orchestrator: InvestigationOrchestrator,
    kind: str,
    expected: str,
    calls: int,
) -> None:
    responses = (
        [ToolExecutionError("fixture failure")]
        if kind == "runtime"
        else [{}]
        if kind == "output"
        else None
    )
    mock = make_mock(responses=responses)
    registry.register(mock.tool)
    if kind == "input":
        plan = InvestigationPlan(
            incident_id=state.incident_id,
            steps=(InvestigationStep(tool_name="log_search", tool_input={}, purpose="Inspect"),),
        )
    result = await orchestrator.execute_step(
        incident_state=state, plan=plan, step_id=plan.steps[0].step_id
    )
    assert result.plan.steps[0].status is InvestigationStepStatus.FAILED
    assert result.plan.steps[0].failure.error_type == expected
    assert result.incident_state == state
    assert mock.call_count == calls


@pytest.mark.asyncio
async def test_mismatch_and_missing_step(
    state: IncidentState,
    plan: InvestigationPlan,
    registry: ToolRegistry,
    orchestrator: InvestigationOrchestrator,
) -> None:
    mock = make_mock()
    registry.register(mock.tool)
    with pytest.raises(InvestigationPlanMismatchError):
        await orchestrator.execute_step(
            incident_state=IncidentState(), plan=plan, step_id=plan.steps[0].step_id
        )
    with pytest.raises(InvestigationStepNotFoundError):
        await orchestrator.execute_step(incident_state=state, plan=plan, step_id=uuid4())
    assert mock.call_count == 0


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.asyncio
async def test_sequential_stops(
    state: IncidentState,
    registry: ToolRegistry,
    orchestrator: InvestigationOrchestrator,
    failure: bool,
) -> None:
    mocks = [
        make_mock(
            name=f"tool_{i}",
            risk=ToolRiskLevel.HIGH if i == 2 and not failure else ToolRiskLevel.READ_ONLY,
            responses=[ToolExecutionError("stop")] if i == 2 and failure else None,
        )
        for i in range(4)
    ]
    for mock in mocks:
        registry.register(mock.tool)
    plan = InvestigationPlan(
        incident_id=state.incident_id,
        steps=tuple(
            InvestigationStep(
                tool_name=mock.tool.metadata.name, tool_input={"user": "alice"}, purpose="Inspect"
            )
            for mock in mocks
        ),
    )
    result = await orchestrator.execute_plan(incident_state=state, plan=plan)
    assert len(result.incident_state.evidence) == 2
    assert [s.status for s in result.plan.steps] == [
        InvestigationStepStatus.COMPLETED,
        InvestigationStepStatus.COMPLETED,
        InvestigationStepStatus.FAILED if failure else InvestigationStepStatus.BLOCKED,
        InvestigationStepStatus.PENDING,
    ]
    assert mocks[3].call_count == 0
    again = await orchestrator.execute_plan(incident_state=result.incident_state, plan=result.plan)
    assert again == result
