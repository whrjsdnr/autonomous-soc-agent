"""Separate fixture-only response harness; never shares investigation authority."""

from datetime import timedelta
from uuid import UUID

from soc_agent.approval import ApprovalManager
from soc_agent.demo.scenario_models import START
from soc_agent.demo.tools import DemoIdentityInput, DemoIdentityOutput, simulate_disable
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import (
    ActionAlreadyAttemptedError,
    ApprovalBindingError,
    ApprovalRejectedError,
    ApprovalRequiredError,
    ExecutionDeniedError,
)
from soc_agent.policy import PolicyEngine
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry


async def response_simulation(
    scenario_id: str, incident: UUID
) -> tuple[str, str, int, tuple[str, ...]]:
    registry = ToolRegistry()
    calls = 0
    events = []

    async def simulate(value: DemoIdentityInput) -> DemoIdentityOutput:
        nonlocal calls
        calls += 1
        return await simulate_disable(value)  # Existing pure simulator; no OS handler.

    registry.register(
        Tool(
            ToolMetadata(
                name="disable_demo_account",
                description="Scenario simulation only",
                permission="system_write",
                risk_level="high",
            ),
            DemoIdentityInput,
            DemoIdentityOutput,
            simulate,
        )
    )
    clock = [START]
    approvals = (
        ApprovalManager(clock=lambda: clock[0]) if scenario_id == "S09" else ApprovalManager()
    )
    executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)
    action = ActionProposal(
        incident_id=incident,
        tool_name="disable_demo_account",
        tool_input={"account_id": "demo-alice"},
    )
    try:
        await executor.execute(action)
    except ApprovalRequiredError:
        events.append("PRE_APPROVAL_DENIED")
    else:
        raise ValueError("SCENARIO_APPROVAL_BYPASS")
    request = executor.request_approval(
        action,
        reason="Fixture-only simulated human review",
        expires_at=START + timedelta(seconds=60) if scenario_id == "S09" else None,
    )
    if scenario_id == "S09":
        approvals.approve(request.approval_id, actor="fixture-human-not-authenticated")
        clock[0] = START + timedelta(seconds=60, microseconds=-1)
        executor.preflight(action, approval_id=request.approval_id)
        events.append("VALID_IMMEDIATELY_BEFORE_EXPIRY")
        for offset in (60, 61):
            clock[0] = START + timedelta(seconds=offset)
            try:
                await executor.execute(action, approval_id=request.approval_id)
            except ExecutionDeniedError:
                events.append("EXPIRED_EXECUTION_DENIED")
            else:
                raise ValueError("SCENARIO_EXPIRY_BYPASS")
        # Rehydrate the exact typed snapshot as a trusted persistence reader would.
        snapshot = type(request).model_validate_json(
            approvals.get(request.approval_id).model_dump_json()
        )
        restored = ApprovalManager(clock=lambda: clock[0])
        restored.restore(snapshot)
        restarted = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=restored)
        try:
            await restarted.execute(action, approval_id=request.approval_id)
        except ExecutionDeniedError:
            return "EXPIRED", "DENIED", calls, (*events, "RESTORED_EXPIRED_APPROVAL_DENIED")
        raise ValueError("SCENARIO_EXPIRED_RESTORE_BYPASS")
    if scenario_id == "S08":
        approvals.reject(request.approval_id, actor="fixture-human-not-authenticated")
        try:
            await executor.execute(action, approval_id=request.approval_id)
        except ApprovalRejectedError:
            return "REJECTED", "DENIED", calls, (*events, "REJECTION_DENIED")
        raise ValueError("SCENARIO_REJECTION_BYPASS")
    approvals.approve(request.approval_id, actor="fixture-human-not-authenticated")
    if scenario_id == "S10":
        changed = ActionProposal.model_validate(
            action.model_dump() | {"tool_input": {"account_id": "demo-bob"}}
        )
        try:
            await executor.execute(changed, approval_id=request.approval_id)
        except ApprovalBindingError:
            return "BINDING_MISMATCH_DENIED", "DENIED", calls, (*events, "BINDING_MISMATCH_DENIED")
        raise ValueError("SCENARIO_BINDING_BYPASS")
    result = await executor.execute(action, approval_id=request.approval_id)
    if not result.output.simulated or result.output.real_system_modified:
        raise ValueError("SCENARIO_SIMULATION_OUTPUT_REJECTED")
    try:
        await executor.execute(action, approval_id=request.approval_id)
    except ActionAlreadyAttemptedError:
        events.append("DUPLICATE_ACTION_DENIED")
    else:
        raise ValueError("SCENARIO_DUPLICATE_BYPASS")
    # Re-evaluation after a trusted registry change is the existing PolicyEngine path.
    changed_registry = ToolRegistry()
    changed_registry.register(
        Tool(
            ToolMetadata(
                name=action.tool_name,
                description="Destructive fixture metadata",
                permission="system_write",
                risk_level="destructive",
            ),
            DemoIdentityInput,
            DemoIdentityOutput,
            simulate,
        )
    )
    changed_executor = GovernedExecutor(
        registry=changed_registry, policy=PolicyEngine(), approvals=approvals
    )
    try:
        await changed_executor.execute(action, approval_id=request.approval_id)
    except ExecutionDeniedError:
        events.append("POLICY_CHANGE_DENIED")
    else:
        raise ValueError("SCENARIO_POLICY_BYPASS")
    return "APPROVED_SIMULATION_ONLY", "SIMULATED", calls, tuple(events)
