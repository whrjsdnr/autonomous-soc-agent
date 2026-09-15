from uuid import uuid4

import pytest

from soc_agent.response import (
    ResponsePlan,
    ResponsePlanMismatchError,
    ResponseStep,
    ResponseStepNotFoundError,
    ResponseStepStateError,
    ResponseStepStatus,
)
from soc_agent.state import IncidentState
from soc_agent.tools import ToolExecutionError, ToolRiskLevel


def make_plan(context, payload):
    state, assessment = context
    return ResponsePlan(
        incident_id=state.incident_id,
        assessment_id=assessment.assessment_id,
        goal=payload["goal"],
        steps=(ResponseStep(**payload["steps"][0]),),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["missing", "pending", "rejected", "approved", "wrong"])
async def test_approval_gate(context, payload, setup_tools, decision):
    state, _ = context
    mock, _, approvals, executor, coordinator = setup_tools()
    plan = make_plan(context, payload)
    step = plan.steps[0]
    action = coordinator.prepare_step(incident_state=state, plan=plan, step_id=step.step_id)
    assert action.action_id == step.action_id
    assert coordinator.prepare_step(incident_state=state, plan=plan, step_id=step.step_id) == action
    approval_id = None
    if decision != "missing":
        if decision == "wrong":
            action = type(action).model_validate(
                action.model_dump() | {"tool_input": {"ip": "other"}}
            )
        request = executor.request_approval(action, reason="Operator review")
        approval_id = request.approval_id
        if decision in ("approved", "wrong"):
            approvals.approve(approval_id, actor="human")
        elif decision == "rejected":
            approvals.reject(approval_id, actor="human")
    result = await coordinator.execute_step(
        incident_state=state, plan=plan, step_id=step.step_id, approval_id=approval_id
    )
    assert result.incident_state == state
    assert plan.steps[0].status is ResponseStepStatus.PENDING
    if decision == "approved":
        assert result.plan.steps[0].status is ResponseStepStatus.COMPLETED
        assert mock.call_count == 1
        with pytest.raises(ResponseStepStateError):
            await coordinator.execute_step(
                incident_state=state, plan=result.plan, step_id=step.step_id
            )
        replay = await coordinator.execute_step(
            incident_state=state, plan=plan, step_id=step.step_id, approval_id=approval_id
        )
        assert replay.plan.steps[0].status is ResponseStepStatus.BLOCKED
        assert mock.call_count == 1
    else:
        assert result.plan.steps[0].status is ResponseStepStatus.BLOCKED
        assert mock.call_count == 0
        expected = {
            "missing": "ApprovalRequiredError",
            "pending": "ApprovalRequiredError",
            "rejected": "ApprovalRejectedError",
            "wrong": "ApprovalBindingError",
        }
        assert result.plan.steps[0].failure.error_type == expected[decision]


@pytest.mark.asyncio
async def test_deny_beats_approved(context, payload, setup_tools):
    state, _ = context
    mock, _, approvals, _, coordinator = setup_tools(ToolRiskLevel.DESTRUCTIVE)
    plan = make_plan(context, payload)
    action = coordinator.prepare_step(
        incident_state=state, plan=plan, step_id=plan.steps[0].step_id
    )
    request = approvals.create(
        incident_id=state.incident_id,
        metadata=mock.tool.metadata,
        reason="Cannot override deny",
        action_id=action.action_id,
        action_input_json=action.tool_input,
    )
    approvals.approve(request.approval_id, actor="human")
    result = await coordinator.execute_step(
        incident_state=state,
        plan=plan,
        step_id=plan.steps[0].step_id,
        approval_id=request.approval_id,
    )
    assert result.plan.steps[0].status is ResponseStepStatus.BLOCKED
    assert result.plan.steps[0].failure.error_type == "ExecutionDeniedError"
    assert mock.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["runtime", "input", "unknown", "none"])
async def test_tool_failures_and_allow(context, payload, setup_tools, failure):
    state, _ = context
    responses = [ToolExecutionError("Fixture failure")] if failure == "runtime" else None
    mock, _, _, _, coordinator = setup_tools(ToolRiskLevel.LOW, responses)
    if failure == "input":
        payload["steps"][0]["tool_input"] = {"missing": True}
    if failure == "unknown":
        payload["steps"][0]["tool_name"] = "not_registered"
    plan = make_plan(context, payload)
    result = await coordinator.execute_step(
        incident_state=state, plan=plan, step_id=plan.steps[0].step_id
    )
    assert result.incident_state == state
    assert result.plan.steps[0].status is (
        ResponseStepStatus.COMPLETED if failure == "none" else ResponseStepStatus.FAILED
    )
    assert mock.call_count == (1 if failure in ("runtime", "none") else 0)
    if failure != "none":
        assert (
            result.plan.steps[0].failure.error_type
            == {
                "runtime": "ToolExecutionError",
                "input": "ToolInputValidationError",
                "unknown": "ToolNotFoundError",
            }[failure]
        )


@pytest.mark.asyncio
async def test_approval_does_not_bypass_schema(context, payload, setup_tools):
    state, _ = context
    mock, _, approvals, executor, coordinator = setup_tools()
    payload["steps"][0]["tool_input"] = {"ip": 123}
    plan = make_plan(context, payload)
    action = coordinator.prepare_step(
        incident_state=state, plan=plan, step_id=plan.steps[0].step_id
    )
    request = executor.request_approval(action, reason="Review")
    approvals.approve(request.approval_id, actor="human")
    result = await coordinator.execute_step(
        incident_state=state,
        plan=plan,
        step_id=plan.steps[0].step_id,
        approval_id=request.approval_id,
    )
    assert result.plan.steps[0].status is ResponseStepStatus.FAILED
    assert result.plan.steps[0].failure.error_type == "ToolInputValidationError"
    assert mock.call_count == 0


def test_lookup_and_incident(context, payload, setup_tools):
    coordinator = setup_tools()[-1]
    plan = make_plan(context, payload)
    with pytest.raises(ResponsePlanMismatchError):
        coordinator.prepare_step(
            incident_state=IncidentState(), plan=plan, step_id=plan.steps[0].step_id
        )
    with pytest.raises(ResponseStepNotFoundError):
        coordinator.prepare_step(incident_state=context[0], plan=plan, step_id=uuid4())


@pytest.mark.asyncio
async def test_sequential_failure_stops_and_does_not_retry(context, payload, setup_tools):
    state, _ = context
    mock, _, _, _, coordinator = setup_tools(
        ToolRiskLevel.LOW, [ToolExecutionError("Uncertain side effect"), {"success": True}]
    )
    plan = make_plan(context, payload)
    second = ResponseStep(**payload["steps"][0])
    plan = ResponsePlan.model_validate(plan.model_dump() | {"steps": (*plan.steps, second)})
    result = await coordinator.execute_plan(incident_state=state, plan=plan)
    assert result.plan.steps[0].status is ResponseStepStatus.FAILED
    assert result.plan.steps[1].status is ResponseStepStatus.PENDING
    again = await coordinator.execute_plan(incident_state=state, plan=result.plan)
    assert again == result
    assert mock.call_count == 1


@pytest.mark.asyncio
async def test_approval_for_other_step_with_identical_input_is_blocked(
    context, payload, setup_tools
) -> None:
    state, _ = context
    mock, _, approvals, executor, coordinator = setup_tools()
    first = make_plan(context, payload)
    second = make_plan(context, payload)
    action = coordinator.prepare_step(
        incident_state=state, plan=first, step_id=first.steps[0].step_id
    )
    request = executor.request_approval(action, reason="Review first action only")
    approvals.approve(request.approval_id, actor="human")
    result = await coordinator.execute_step(
        incident_state=state,
        plan=second,
        step_id=second.steps[0].step_id,
        approval_id=request.approval_id,
    )
    assert result.plan.steps[0].status is ResponseStepStatus.BLOCKED
    assert result.plan.steps[0].failure.error_type == "ApprovalBindingError"
    assert mock.call_count == 0


@pytest.mark.asyncio
async def test_invalid_output_fails_without_retry(context, payload, setup_tools) -> None:
    state, _ = context
    mock, _, _, _, coordinator = setup_tools(ToolRiskLevel.LOW, [{}, {"success": True}])
    plan = make_plan(context, payload)
    result = await coordinator.execute_plan(incident_state=state, plan=plan)
    assert result.plan.steps[0].status is ResponseStepStatus.FAILED
    assert result.plan.steps[0].failure.error_type == "ToolOutputValidationError"
    with pytest.raises(ResponseStepStateError):
        await coordinator.execute_step(
            incident_state=state, plan=result.plan, step_id=plan.steps[0].step_id
        )
    assert mock.call_count == 1
