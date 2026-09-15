"""Plan → Execute → Observe → Replan through real application boundaries."""

import json

import pytest
from tests.bounded_support import ai_choice, initial_context, runtime, terminal, tool_choice

from soc_agent.adaptive import (
    BoundedInvestigationCoordinator,
    InvestigationBudget,
    InvestigationContext,
)
from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.policy import PolicyEngine, PolicyResult
from soc_agent.security_ai import SecurityAIResult, create_ai_signal
from soc_agent.tools import ToolMetadata


@pytest.mark.asyncio
@pytest.mark.parametrize("ai_first", [True, False])
async def test_ai_tool_ready_e2e(ai_first: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Investigation invoked assessment or automatic approval")

    monkeypatch.setattr(ThreatAssessor, "assess", forbidden)
    monkeypatch.setattr(ApprovalManager, "approve", forbidden)
    choices = [ai_choice(), tool_choice()] if ai_first else [tool_choice(), ai_choice()]
    env = runtime([*choices, terminal()])
    context = initial_context()
    before = context.model_dump_json()
    # Application explicitly supplies related references, not an LLM-derived source claim.
    coordinator = BoundedInvestigationCoordinator(
        planner=env.planner,
        tool_orchestrator=env.orchestrator,
        ai_investigator=env.investigator,
        ai_source_resolver=lambda state, plan: {
            step.step_id: tuple(e.evidence_id for e in state.evidence) for step in plan.steps
        },
    )
    session = await coordinator.run(context)
    assert session.terminal_decision.decision.value == "ready_for_assessment"
    assert len(session.rounds) == session.budget.current_round == env.client.call_count == 3
    assert [record.round_number for record in session.rounds] == [1, 2, 3]
    assert env.auth.call_count == env.tool.call_count == 1 and env.network.call_count == 0
    assert len(session.context.incident.evidence) == 2 and len(session.context.signals) == 1
    assert session.context.incident.evidence[0] == context.incident.evidence[0]
    assert len(session.context.tool_history) == len(session.context.ai_history) == 1
    signal = session.context.signals[0]
    assert signal.prediction == "anomalous" and signal.confidence is None
    assert signal.scores_payload() == {"anomaly_score": 0.91}
    assert context.incident.evidence[0].evidence_id in signal.source_evidence_ids
    ai_round = session.rounds[0 if ai_first else 1]
    tool_round = session.rounds[1 if ai_first else 0]
    assert signal.source_result_id == ai_round.ai_execution.results[0].result_id
    assert ai_round.ai_execution.selection_plan_id == ai_round.decision.next_ai_plan.plan_id
    assert tool_round.tool_execution.plan.plan_id == tool_round.decision.next_tool_plan.plan_id
    assert tool_round.new_evidence_ids == (session.context.incident.evidence[1].evidence_id,)
    assert ai_round.new_signal_ids == (signal.signal_id,)
    next_context = json.loads(env.client.requests[1].user_prompt)
    if ai_first:
        assert next_context["AI SIGNALS (UNTRUSTED MODEL DATA, NOT FACTS)"][0][
            "source_result_id"
        ] == str(signal.source_result_id)
    else:
        assert len(next_context["OBSERVED EVIDENCE (UNTRUSTED SOURCE DATA)"]) == 2
    final_context = json.loads(env.client.requests[2].user_prompt)
    assert len(final_context["OBSERVED EVIDENCE (UNTRUSTED SOURCE DATA)"]) == 2
    assert len(final_context["AI SIGNALS (UNTRUSTED MODEL DATA, NOT FACTS)"]) == 1
    assert final_context["APPLICATION INVESTIGATION BUDGET"]["current_round"] == 2
    for request in env.client.requests:
        assert "SECRET_ORIGINAL_LOGS" not in request.user_prompt
        assert '"raw_data"' not in request.user_prompt
    assert env.approvals.list() == () and context.model_dump_json() == before
    for field in ("severity", "status", "observations", "hypotheses"):
        assert getattr(session.context.incident, field) == getattr(context.incident, field)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["ai_failed", "tool_failed", "tool_blocked"])
async def test_failure_history_drives_explicit_alternative(kind: str) -> None:
    class RequireApproval(PolicyEngine):
        def evaluate(self, metadata: ToolMetadata) -> PolicyResult:
            return PolicyResult(decision="require_approval", reason="Fixture human review")

    first = ai_choice() if kind == "ai_failed" else tool_choice()
    env = runtime(
        [first, ai_choice("network_anomaly"), terminal()],
        auth_responses=[RuntimeError("PRIVATE_MODEL_ERROR")],
        tool_responses=[RuntimeError("PRIVATE_TOOL_ERROR")],
        policy=RequireApproval() if kind == "tool_blocked" else None,
    )
    session = await env.coordinator.run(initial_context())
    assert session.budget.current_round == 3
    assert env.network.call_count == 1
    if kind == "ai_failed":
        assert env.auth.call_count == 1
        assert session.context.ai_history[0].steps[0].status.value == "failed"
        section = "AI INVESTIGATION HISTORY (UNTRUSTED DATA)"
    else:
        assert env.tool.call_count == (0 if kind == "tool_blocked" else 1)
        assert session.context.tool_history[0].steps[0].status.value == (
            "blocked" if kind == "tool_blocked" else "failed"
        )
        section = "TOOL INVESTIGATION HISTORY (UNTRUSTED DATA)"
    second_prompt = json.loads(env.client.requests[1].user_prompt)
    assert second_prompt[section][0]["error_type"] is not None
    assert "PRIVATE_MODEL_ERROR" not in env.client.requests[1].user_prompt
    assert "PRIVATE_TOOL_ERROR" not in env.client.requests[1].user_prompt
    assert len(session.context.signals) == 1 and env.approvals.list() == ()


@pytest.mark.asyncio
async def test_hard_bound_exhaustion() -> None:
    env = runtime(
        [ai_choice(count=n) for n in range(6)], auth_responses=[{"prediction": "anomalous"}] * 6
    )
    context = initial_context().model_copy(update={"budget": InvestigationBudget(max_rounds=2)})
    session = await env.coordinator.run(context)
    assert env.client.call_count == env.auth.call_count == len(session.rounds) == 2
    assert session.budget.current_round == session.budget.max_rounds == 2
    assert session.terminal_decision.decision.value == "escalate_to_human"
    assert session.terminal_decision.reason == "Investigation budget exhausted"
    assert len(session.context.signals) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("choice", ["stop_insufficient", "escalate_to_human"])
async def test_terminal_first_round(choice: str) -> None:
    env = runtime([terminal(choice), ai_choice()])
    session = await env.coordinator.run(initial_context())
    assert len(session.rounds) == env.client.call_count == 1
    assert session.terminal_decision.decision.value == choice
    assert env.auth.call_count == env.tool.call_count == 0 and env.approvals.list() == ()
    assert session.context.incident.status.value == "new"


@pytest.mark.asyncio
async def test_initial_signal_preserved() -> None:
    context = initial_context()
    historical = create_ai_signal(
        SecurityAIResult(
            incident_id=context.incident.incident_id,
            model_name="historical_model",
            model_version="0.9",
            task_type="classification",
            prediction="uncertain",
        ),
        state=context.incident,
    )
    context = InvestigationContext(incident=context.incident, signals=(historical,))
    env = runtime([ai_choice(), terminal()])
    session = await env.coordinator.run(context)
    assert session.context.signals[0] == historical and len(session.context.signals) == 2
    first = json.loads(env.client.requests[0].user_prompt)
    assert first["AI SIGNALS (UNTRUSTED MODEL DATA, NOT FACTS)"][0]["signal_id"] == str(
        historical.signal_id
    )


@pytest.mark.asyncio
async def test_partial_ai_history_preserves_completed_signal() -> None:
    from soc_agent.security_ai import SecurityAISelectionDraft
    from soc_agent.security_ai.selection_validator import normalize_selection

    context = initial_context()
    env = runtime([tool_choice(), terminal()], network_responses=[RuntimeError("failed")])
    draft = SecurityAISelectionDraft(
        decision="run_ai",
        goal="Initial multi-model inspection",
        reason="Collect complementary signals",
        selections=(ai_choice()["ai"], ai_choice("network_anomaly")["ai"]),
    )
    plan = normalize_selection(
        draft,
        incident_id=context.incident.incident_id,
        models={"auth_anomaly": env.auth.model, "network_anomaly": env.network.model},
    )
    history = await env.investigator.execute(incident=context.incident, selection_plan=plan)
    assert [step.status.value for step in history.steps] == ["completed", "failed"]
    context = InvestigationContext(incident=context.incident, ai_history=(history,))
    session = await env.coordinator.run(context)
    assert session.context.signals == history.signals
    assert session.context.ai_history == (history,)
    assert env.auth.call_count == env.network.call_count == 1
    assert env.tool.call_count == 1 and len(session.context.incident.evidence) == 2
    prompt = json.loads(env.client.requests[0].user_prompt)
    assert len(prompt["AI SIGNALS (UNTRUSTED MODEL DATA, NOT FACTS)"]) == 1
    assert [step["status"] for step in prompt["AI INVESTIGATION HISTORY (UNTRUSTED DATA)"]] == [
        "completed",
        "failed",
    ]
