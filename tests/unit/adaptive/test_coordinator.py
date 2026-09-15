import asyncio
from collections.abc import Callable
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.bounded_support import (
    Features,
    Query,
    Reputation,
    Runtime,
    ai_choice,
    initial_context,
    runtime,
    terminal,
    tool_choice,
)

from soc_agent.adaptive import (
    AdaptiveInvestigationDecision,
    AdaptiveInvestigationPlanner,
    AutonomousInvestigationSession,
    BoundedInvestigationCoordinator,
    BoundedInvestigationError,
    InvestigationBudget,
    InvestigationContext,
)
from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.investigation import InvestigationOrchestrator
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAI,
    SecurityAIInvestigator,
    SecurityAIRegistry,
    SecurityAIResult,
    create_ai_signal,
)
from soc_agent.state import IncidentState
from soc_agent.tools import MockTool, ToolRegistry


@pytest.mark.asyncio
@pytest.mark.parametrize("current", [5, 7])
async def test_initial_exhaustion_no_calls(
    current: int, bounded_runtime: Callable[..., Runtime]
) -> None:
    env = bounded_runtime([])
    context = initial_context().model_copy(
        update={"budget": InvestigationBudget(current_round=current)}
    )
    session = await env.coordinator.run(context)
    assert session.rounds == () and session.budget.current_round == current
    assert session.terminal_decision.decision.value == "escalate_to_human"
    assert env.client.call_count == env.auth.call_count == env.tool.call_count == 0


@pytest.mark.asyncio
async def test_remaining_budget_and_immutability() -> None:
    env = runtime([ai_choice(), terminal()])
    context = initial_context().model_copy(update={"budget": InvestigationBudget(current_round=4)})
    session = await env.coordinator.run(context)
    assert [r.round_number for r in session.rounds] == [5]
    assert env.client.call_count == 1 and session.budget.current_round == 5
    assert context.budget.current_round == 4
    assert AutonomousInvestigationSession.model_validate_json(session.model_dump_json()) == session
    with pytest.raises(ValidationError):
        session.session_id = uuid4()
    with pytest.raises(ValidationError):
        session.rounds[0].round_number = 99
    with pytest.raises(ValidationError):
        session.context.signals[0].prediction = "changed"


@pytest.mark.parametrize(
    "kind", ["cross_signal", "duplicate_signal", "duplicate_result", "empty", "corrupt_budget"]
)
@pytest.mark.asyncio
async def test_invalid_initial_context(kind: str) -> None:
    context = initial_context()
    signal = create_ai_signal(
        SecurityAIResult(
            incident_id=context.incident.incident_id,
            model_name="historical",
            model_version="1",
            task_type="classification",
            prediction="benign",
        ),
        state=context.incident,
    )
    if kind == "cross_signal":
        context = InvestigationContext(incident=IncidentState(), signals=(signal,))
    elif kind == "duplicate_signal":
        context = context.model_copy(update={"signals": (signal, signal)})
    elif kind == "duplicate_result":
        context = context.model_copy(
            update={"signals": (signal, signal.model_copy(update={"signal_id": uuid4()}))}
        )
    elif kind == "empty":
        context = InvestigationContext(incident=IncidentState())
    else:
        context = context.model_copy(
            update={"budget": InvestigationBudget.model_construct(current_round=-1)}
        )
    env = runtime([])
    with pytest.raises(BoundedInvestigationError) as caught:
        await env.coordinator.run(context)
    assert caught.value.session is None and env.client.call_count == 0


@pytest.mark.parametrize(
    "invalid",
    [
        ai_choice(),
        tool_choice("unrestricted_shell"),
        ai_choice("unknown_ai"),
        {"decision": "ready_for_assessment", "reason": "", "tool": None, "ai": None},
    ],
)
@pytest.mark.asyncio
async def test_planning_error_keeps_progress_without_retry(invalid: dict[str, object]) -> None:
    env = runtime([ai_choice(), invalid, terminal()])
    context = initial_context()
    with pytest.raises(BoundedInvestigationError) as caught:
        await env.coordinator.run(context)
    partial = caught.value.session
    assert caught.value.__cause__ is not None
    assert len(partial.context.signals) == len(partial.context.ai_history) == 1
    assert len(partial.rounds) == partial.budget.current_round == 2
    assert partial.rounds[-1].error_type and partial.rounds[-1].failure_stage == "planning"
    assert partial.terminal_decision is None
    assert env.auth.call_count == 1 and env.client.call_count == 2


@pytest.mark.asyncio
async def test_ai_version_drift_blocked_then_replanned() -> None:
    env = runtime([ai_choice(), tool_choice(), terminal()])
    replacement = MockSecurityAI(
        metadata=env.auth.model.metadata.model_copy(update={"version": "2.0"}),
        input_model=Features,
        responses=[],
    )
    current = SecurityAIRegistry()
    current.register(replacement.model)
    coordinator = BoundedInvestigationCoordinator(
        planner=env.planner,
        tool_orchestrator=env.orchestrator,
        ai_investigator=SecurityAIInvestigator(registry=current),
    )
    session = await coordinator.run(initial_context())
    assert session.context.ai_history[0].steps[0].status.value == "blocked"
    assert replacement.call_count == env.auth.call_count == 0
    assert (
        env.tool.call_count == 1
        and session.terminal_decision.decision.value == "ready_for_assessment"
    )
    assert "blocked" in env.client.requests[1].user_prompt


@pytest.mark.parametrize("risk", ["low", "high", "destructive"])
@pytest.mark.asyncio
async def test_read_only_rechecked_at_execution(risk: str) -> None:
    env = runtime([tool_choice(), ai_choice(), terminal()])
    write_tool = MockTool(
        metadata=env.tool.tool.metadata.model_copy(
            update={"permission": "network_write", "risk_level": risk}
        ),
        input_model=Query,
        output_model=Reputation,
        responses=[],
    )
    current = ToolRegistry()
    current.register(write_tool.tool)
    approvals = ApprovalManager()
    orchestrator = InvestigationOrchestrator(
        executor=GovernedExecutor(registry=current, policy=PolicyEngine(), approvals=approvals)
    )
    coordinator = BoundedInvestigationCoordinator(
        planner=env.planner, tool_orchestrator=orchestrator, ai_investigator=env.investigator
    )
    session = await coordinator.run(initial_context())
    failed = session.context.tool_history[0].steps[0]
    assert failed.status.value == "blocked" and failed.failure.error_type == "ExecutionDeniedError"
    assert "observation-only" in failed.failure.reason
    assert write_tool.call_count == env.tool.call_count == 0 and approvals.list() == ()
    assert env.auth.call_count == 1


@pytest.mark.parametrize("kind", ["incident", "budget", "payload"])
@pytest.mark.asyncio
async def test_corrupted_planner_decision_never_executes(kind: str) -> None:
    env = runtime([ai_choice()])

    class CorruptPlanner(AdaptiveInvestigationPlanner):
        async def replan(self, context: InvestigationContext) -> AdaptiveInvestigationDecision:
            decision = await env.planner.replan(context)
            if kind == "incident":
                return decision.model_copy(update={"incident_id": uuid4()})
            if kind == "budget":
                return decision.model_copy(update={"budget": InvestigationBudget(max_rounds=999)})
            return decision.model_copy(update={"decision": "ready_for_assessment"})

    coordinator = BoundedInvestigationCoordinator(
        planner=CorruptPlanner(
            llm_client=env.client, tool_registry=env.tools, ai_registry=env.models
        ),
        tool_orchestrator=env.orchestrator,
        ai_investigator=env.investigator,
    )
    with pytest.raises(BoundedInvestigationError) as caught:
        await coordinator.run(initial_context())
    assert caught.value.session.budget.max_rounds == 5
    assert caught.value.session.budget.current_round == 1
    assert env.auth.call_count == env.tool.call_count == 0


@pytest.mark.asyncio
async def test_cancel_propagates_without_replay() -> None:
    env = runtime([tool_choice(), ai_choice(), terminal()])
    calls = []

    async def cancel(request: object) -> object:
        calls.append(request)
        raise asyncio.CancelledError()

    current = SecurityAIRegistry()
    current.register(SecurityAI(env.auth.model.metadata, Features, cancel))
    coordinator = BoundedInvestigationCoordinator(
        planner=env.planner,
        tool_orchestrator=env.orchestrator,
        ai_investigator=SecurityAIInvestigator(registry=current),
    )
    with pytest.raises(asyncio.CancelledError):
        await coordinator.run(initial_context())
    assert len(calls) == 1 and env.tool.call_count == 1 and env.client.call_count == 2


@pytest.mark.asyncio
async def test_application_source_binding_block_is_history() -> None:
    env = runtime([ai_choice(), terminal("escalate_to_human")])
    coordinator = BoundedInvestigationCoordinator(
        planner=env.planner,
        tool_orchestrator=env.orchestrator,
        ai_investigator=env.investigator,
        ai_source_resolver=lambda state, plan: {plan.steps[0].step_id: (uuid4(),)},
    )
    session = await coordinator.run(initial_context())
    assert session.context.ai_history[0].steps[0].status.value == "blocked"
    assert session.context.signals == () and env.auth.call_count == 0


@pytest.mark.parametrize(
    "kind", ["round", "budget", "terminal", "evidence", "signal", "plan", "time"]
)
@pytest.mark.asyncio
async def test_session_rejects_inconsistent_provenance(kind: str) -> None:
    env = runtime([ai_choice(), tool_choice(), terminal()])
    session = await env.coordinator.run(initial_context())
    data = session.model_dump()
    if kind == "round":
        data["rounds"][1]["round_number"] = 4
    elif kind == "budget":
        data["context"]["budget"]["current_round"] = 0
    elif kind == "terminal":
        data["terminal_decision"] = None
    elif kind == "evidence":
        data["context"]["incident"]["evidence"][0]["summary"] = "forged"
    elif kind == "signal":
        data["rounds"][0]["new_signal_ids"] = (uuid4(),)
    elif kind == "plan":
        data["rounds"][1]["tool_execution"]["plan"]["plan_id"] = uuid4()
    else:
        data["rounds"][0]["completed_at"] = session.created_at
    with pytest.raises(ValidationError):
        AutonomousInvestigationSession.model_validate(data)


@pytest.mark.asyncio
async def test_corrupt_execution_preserves_only_accepted_progress() -> None:
    env = runtime([ai_choice(), tool_choice(), terminal()])

    class WrongIncidentOrchestrator(InvestigationOrchestrator):
        async def execute_plan(self, **kwargs: object) -> object:
            result = await env.orchestrator.execute_plan(**kwargs)
            return result.model_copy(update={"incident_state": IncidentState()})

    coordinator = BoundedInvestigationCoordinator(
        planner=env.planner,
        tool_orchestrator=WrongIncidentOrchestrator(executor=None),
        ai_investigator=env.investigator,
    )
    with pytest.raises(BoundedInvestigationError) as caught:
        await coordinator.run(initial_context())
    partial = caught.value.session
    assert len(partial.context.signals) == 1 and len(partial.context.incident.evidence) == 1
    assert partial.rounds[-1].failure_stage == "validation"
    assert env.client.call_count == 2 and env.tool.call_count == 1
