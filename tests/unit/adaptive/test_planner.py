import json
from datetime import timedelta

import pytest
from pydantic import JsonValue, ValidationError

from soc_agent.adaptive import (
    AdaptiveContextTooLargeError,
    AdaptiveInvestigationDecision,
    AdaptiveInvestigationPlanner,
    AdaptivePlanningError,
    InvalidInvestigationContextError,
    InvestigationBudget,
    InvestigationContext,
    RepeatedInvestigationError,
    ReplanningDraft,
)
from soc_agent.llm import LLMResponseValidationError, MockLLMClient
from soc_agent.planning import InvalidPlannedToolInputError, UnknownPlannedToolError
from soc_agent.security_ai import (
    InvalidSelectedModelInputError,
    MockSecurityAI,
    SecurityAIRegistry,
    UnknownSelectedModelError,
)
from soc_agent.state import IncidentState
from soc_agent.tools import MockTool, ToolMetadata, ToolRegistry

from .conftest import AuthInput, LookupInput, LookupOutput, ai_history, response, tool_history


def planner(
    client: MockLLMClient, tools: ToolRegistry, models: SecurityAIRegistry
) -> AdaptiveInvestigationPlanner:
    return AdaptiveInvestigationPlanner(llm_client=client, tool_registry=tools, ai_registry=models)


@pytest.mark.parametrize(
    "choice",
    [
        "continue_with_tool",
        "continue_with_ai",
        "ready_for_assessment",
        "stop_insufficient",
        "escalate_to_human",
    ],
)
@pytest.mark.asyncio
async def test_decisions(
    choice: str,
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
    mock_tool: MockTool,
    mock_ai: MockSecurityAI,
) -> None:
    client = MockLLMClient([response(choice)])
    before = context.model_dump_json()
    result = await planner(client, tools, models).replan(context)
    assert result.decision.value == choice
    assert result.decision_id.version == 4 and result.created_at.utcoffset() == timedelta(0)
    assert result.incident_id == context.incident.incident_id and result.budget == context.budget
    assert AdaptiveInvestigationDecision.model_validate_json(result.model_dump_json()) == result
    if choice == "continue_with_tool":
        plan = result.next_tool_plan
        assert plan.incident_id == context.incident.incident_id
        assert len(plan.steps) == 1 and plan.steps[0].status.value == "pending"
        assert plan.steps[0].tool_input == '{"indicator":"203.0.113.7","limit":10}'
    elif choice == "continue_with_ai":
        plan = result.next_ai_plan
        assert plan.incident_id == context.incident.incident_id
        assert len(plan.steps) == 1 and plan.steps[0].model_version == "1.0"
        assert plan.steps[0].input_payload() == {"failed_login_count": 43, "unique_accounts": 7}
    else:
        assert result.next_tool_plan is result.next_ai_plan is None
    assert client.call_count == 1 and mock_ai.call_count == mock_tool.call_count == 0
    assert context.model_dump_json() == before
    with pytest.raises(ValidationError):
        result.reason = "changed"


@pytest.mark.parametrize(
    "field",
    [
        "permission",
        "risk",
        "approval",
        "policy",
        "model_version",
        "task_type",
        "input_type",
        "incident_id",
        "action_id",
        "result_id",
        "signal_id",
        "status",
        "severity",
        "max_rounds",
        "budget",
    ],
)
@pytest.mark.parametrize("location", ["top", "tool", "ai"])
@pytest.mark.asyncio
async def test_extra_fields_forbidden(
    field: str,
    location: str,
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
) -> None:
    payload = response("continue_with_ai" if location == "ai" else "continue_with_tool")
    target = payload if location == "top" else payload[location]
    target[field] = "forged"
    client = MockLLMClient([payload])
    with pytest.raises(LLMResponseValidationError):
        await planner(client, tools, models).replan(context)
    assert client.call_count == 1


@pytest.mark.parametrize(
    "choice",
    [
        "continue_with_tool",
        "continue_with_ai",
        "ready_for_assessment",
        "stop_insufficient",
        "escalate_to_human",
    ],
)
@pytest.mark.parametrize("tool,ai", [(False, False), (True, False), (False, True), (True, True)])
def test_draft_consistency(choice: str, tool: bool, ai: bool) -> None:
    payload = response(choice) | {
        "tool": response("continue_with_tool")["tool"] if tool else None,
        "ai": response("continue_with_ai")["ai"] if ai else None,
    }
    valid = tool == (choice == "continue_with_tool") and ai == (choice == "continue_with_ai")
    if valid:
        ReplanningDraft.model_validate(payload)
    else:
        with pytest.raises(ValidationError):
            ReplanningDraft.model_validate(payload)


@pytest.mark.parametrize(
    "choice,name,error",
    [
        ("continue_with_tool", "unrestricted_shell", UnknownPlannedToolError),
        ("continue_with_ai", "super_zero_day_ai", UnknownSelectedModelError),
    ],
)
@pytest.mark.asyncio
async def test_allowlist_no_retry(
    choice: str,
    name: str,
    error: type[Exception],
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
    mock_tool: MockTool,
    mock_ai: MockSecurityAI,
) -> None:
    client = MockLLMClient([response(choice, name=name), response("stop_insufficient")])
    with pytest.raises(error):
        await planner(client, tools, models).replan(context)
    assert client.call_count == 1 and mock_tool.call_count == mock_ai.call_count == 0


@pytest.mark.parametrize(
    "choice,value,error",
    [
        ("continue_with_tool", {"indicator": 5}, InvalidPlannedToolInputError),
        ("continue_with_ai", {"failed_login_count": "many"}, InvalidSelectedModelInputError),
    ],
)
@pytest.mark.asyncio
async def test_input_schema_reused(
    choice: str,
    value: JsonValue,
    error: type[Exception],
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
) -> None:
    with pytest.raises(error):
        await planner(MockLLMClient([response(choice, value=value)]), tools, models).replan(context)


@pytest.mark.parametrize("current", [5, 6])
@pytest.mark.asyncio
async def test_budget_exhausted(
    current: int, context: InvestigationContext, tools: ToolRegistry, models: SecurityAIRegistry
) -> None:
    context = context.model_copy(update={"budget": InvestigationBudget(current_round=current)})
    client = MockLLMClient([])
    result = await planner(client, tools, models).replan(context)
    assert result.decision.value == "escalate_to_human"
    assert result.reason == "Investigation budget exhausted" and client.call_count == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"max_rounds": 0},
        {"current_round": -1},
        {"current_round": True},
        {"max_rounds": "5"},
        {"extra": 2},
    ],
)
def test_budget_validation(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        InvestigationBudget.model_validate(payload)
    with pytest.raises(ValidationError):
        InvestigationBudget().max_rounds = 1000


@pytest.mark.parametrize("kind", ["tool", "ai"])
@pytest.mark.parametrize("status", ["completed", "failed", "blocked"])
@pytest.mark.asyncio
async def test_exact_history_loop(
    kind: str,
    status: str,
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
) -> None:
    history = (
        tool_history(context, tools, status)
        if kind == "tool"
        else ai_history(context, models, status)
    )
    context = context.model_copy(update={f"{kind}_history": (history,)})
    before = context.model_dump_json()
    client = MockLLMClient([response(f"continue_with_{kind}")])
    with pytest.raises(RepeatedInvestigationError):
        await planner(client, tools, models).replan(context)
    assert client.call_count == 1 and context.model_dump_json() == before


@pytest.mark.parametrize("kind", ["tool", "ai"])
@pytest.mark.asyncio
async def test_different_input_allowed(
    kind: str, context: InvestigationContext, tools: ToolRegistry, models: SecurityAIRegistry
) -> None:
    history = tool_history(context, tools) if kind == "tool" else ai_history(context, models)
    context = context.model_copy(update={f"{kind}_history": (history,)})
    value = {"indicator": "203.0.113.8"} if kind == "tool" else {"failed_login_count": 44}
    result = await planner(
        MockLLMClient([response(f"continue_with_{kind}", value=value)]), tools, models
    ).replan(context)
    assert result.decision.value == f"continue_with_{kind}"


@pytest.mark.parametrize(
    "kind",
    [
        "signal",
        "tool_history",
        "ai_history",
        "duplicate_signal",
        "duplicate_history",
        "unknown_evidence",
        "conflicting_signal",
        "empty",
        "bypassed_budget",
    ],
)
@pytest.mark.asyncio
async def test_context_rejected_before_llm(
    kind: str, context: InvestigationContext, tools: ToolRegistry, models: SecurityAIRegistry
) -> None:
    history = ai_history(context, models, "completed")
    signal = history.signals[0]
    if kind == "signal":
        context = context.model_copy(update={"signals": (signal,), "incident": IncidentState()})
    elif kind == "tool_history":
        context = InvestigationContext(
            incident=IncidentState(), tool_history=(tool_history(context, tools),)
        )
    elif kind == "ai_history":
        context = InvestigationContext(incident=IncidentState(), ai_history=(history,))
    elif kind == "duplicate_signal":
        context = context.model_copy(update={"signals": (signal, signal)})
    elif kind == "duplicate_history":
        context = context.model_copy(update={"ai_history": (history, history)})
    elif kind == "unknown_evidence":
        prior = tool_history(context, tools, "completed")
        context = InvestigationContext(
            incident=IncidentState(incident_id=context.incident.incident_id), tool_history=(prior,)
        )
    elif kind == "conflicting_signal":
        context = context.model_copy(
            update={
                "signals": (signal.model_copy(update={"prediction": "different"}),),
                "ai_history": (history,),
            }
        )
    elif kind == "bypassed_budget":
        context = context.model_copy(
            update={"budget": InvestigationBudget.model_construct(current_round=-1)}
        )
    else:
        context = InvestigationContext(incident=IncidentState())
    client = MockLLMClient([])
    with pytest.raises(InvalidInvestigationContextError):
        await planner(client, tools, models).replan(context)
    assert client.call_count == 0


@pytest.mark.asyncio
async def test_signal_merge_history_context_privacy(
    context: InvestigationContext, tools: ToolRegistry, models: SecurityAIRegistry
) -> None:
    history = ai_history(context, models, "completed")
    failed = tool_history(context, tools, "failed")
    context = context.model_copy(
        update={"ai_history": (history,), "tool_history": (failed,), "signals": history.signals}
    )
    client = MockLLMClient([response("ready_for_assessment")])
    await planner(client, tools, models).replan(context)
    request = client.requests[0]
    data = json.loads(request.user_prompt)
    signals = data["AI SIGNALS (UNTRUSTED MODEL DATA, NOT FACTS)"]
    assert len(signals) == 1 and signals[0]["source_result_id"] == str(history.results[0].result_id)
    assert signals[0]["prediction"] == "credential_attack" and signals[0]["confidence"] == 0.94
    assert "observed_at" in data["OBSERVED EVIDENCE (UNTRUSTED SOURCE DATA)"][0]
    assert data["TOOL INVESTIGATION HISTORY (UNTRUSTED DATA)"][0]["error_type"] == "FixtureFailure"
    assert data["AI INVESTIGATION HISTORY (UNTRUSTED DATA)"][0]["signal_id"] == str(
        history.signals[0].signal_id
    )
    for secret in (
        "SECRET_RAW_DATA",
        "SECRET_TRACEBACK",
        "raw_data",
        "tool_input",
        "model_input",
        "<function",
    ):
        assert secret not in request.user_prompt
    assert "unrestricted_shell" not in request.system_prompt


@pytest.mark.parametrize("source", ["summary", "signal", "history", "catalog"])
@pytest.mark.asyncio
async def test_context_budget(
    source: str,
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
    mock_ai: MockSecurityAI,
) -> None:
    if source == "summary":
        data = context.model_dump()
        data["incident"]["evidence"][0]["summary"] = "x" * 64000
        context = InvestigationContext.model_validate(data)
    elif source == "signal":
        signal = ai_history(context, models, "completed").signals[0]
        context = context.model_copy(
            update={
                "signals": (
                    signal.model_copy(update={"explanation": '{"text":"' + "x" * 64000 + '"}'}),
                )
            }
        )
    elif source == "history":
        history = tool_history(context, tools)
        data = history.model_dump()
        data["steps"][0]["purpose"] = "x" * 64000
        context = context.model_copy(update={"tool_history": (type(history).model_validate(data),)})
    else:
        other = MockSecurityAI(
            metadata=mock_ai.model.metadata.model_copy(
                update={"name": "big_model", "description": "x" * 64000}
            ),
            input_model=AuthInput,
            responses=[],
        )
        models.register(other.model)
    client = MockLLMClient([])
    with pytest.raises(AdaptiveContextTooLargeError):
        await planner(client, tools, models).replan(context)
    assert client.call_count == 0


@pytest.mark.parametrize(
    "risk,permission",
    [("high", "network_read"), ("destructive", "system_write"), ("low", "system_write")],
)
@pytest.mark.asyncio
async def test_response_capability_excluded(
    risk: str,
    permission: str,
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
) -> None:
    risky = MockTool(
        metadata=ToolMetadata(
            name="risky_tool",
            description="Response capability",
            permission=permission,
            risk_level=risk,
        ),
        input_model=LookupInput,
        output_model=LookupOutput,
        responses=[],
    )
    tools.register(risky.tool)
    client = MockLLMClient([response("continue_with_tool", name="risky_tool")])
    with pytest.raises(UnknownPlannedToolError):
        await planner(client, tools, models).replan(context)
    assert "risky_tool" not in client.requests[0].user_prompt and risky.call_count == 0


@pytest.mark.asyncio
async def test_empty_catalog_still_allows_readiness(context: InvestigationContext) -> None:
    client = MockLLMClient([response("ready_for_assessment")])
    result = await planner(client, ToolRegistry(), SecurityAIRegistry()).replan(context)
    assert result.decision.value == "ready_for_assessment" and client.call_count == 1


@pytest.mark.asyncio
async def test_ready_requires_assessor_evidence(
    context: InvestigationContext, tools: ToolRegistry, models: SecurityAIRegistry
) -> None:
    history = ai_history(context, models, "completed")
    context = InvestigationContext(
        incident=IncidentState(incident_id=context.incident.incident_id), signals=history.signals
    )
    with pytest.raises(AdaptivePlanningError, match="observed evidence"):
        await planner(MockLLMClient([response("ready_for_assessment")]), tools, models).replan(
            context
        )
