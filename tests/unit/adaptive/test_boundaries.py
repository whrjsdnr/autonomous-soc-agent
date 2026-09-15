import asyncio
import json
from datetime import datetime

import pytest
from pydantic import BaseModel, ValidationError

from soc_agent.adaptive import AdaptiveInvestigationDecision, InvestigationContext
from soc_agent.adaptive.context import validate_context
from soc_agent.adaptive.prompts import build_replanning_request
from soc_agent.llm import LLMRequest, LLMTimeoutError, MockLLMClient
from soc_agent.planning import UnknownPlannedToolError
from soc_agent.security_ai import MockSecurityAI, SecurityAIRegistry, UnknownSelectedModelError
from soc_agent.tools import MockTool, ToolRegistry

from .conftest import AuthInput, LookupInput, LookupOutput, ai_history, response, tool_history
from .test_planner import planner


@pytest.mark.parametrize("error", [LLMTimeoutError("fixture timeout"), asyncio.CancelledError()])
@pytest.mark.asyncio
async def test_llm_error_propagates(
    error: BaseException,
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
) -> None:
    class FailingClient(MockLLMClient):
        async def generate_structured[T: BaseModel](
            self, *, request: LLMRequest, response_model: type[T]
        ) -> T:
            await super().generate_structured(request=request, response_model=response_model)
            raise error

    client = FailingClient([response("stop_insufficient")])
    with pytest.raises(type(error)) as caught:
        await planner(client, tools, models).replan(context)
    assert caught.value is error and client.call_count == 1


def test_catalog_context_determinism(
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
    mock_tool: MockTool,
    mock_ai: MockSecurityAI,
) -> None:
    tools.register(
        MockTool(
            metadata=mock_tool.tool.metadata.model_copy(update={"name": "aaa_lookup"}),
            input_model=LookupInput,
            output_model=LookupOutput,
            responses=[],
        ).tool
    )
    models.register(
        MockSecurityAI(
            metadata=mock_ai.model.metadata.model_copy(update={"name": "aaa_model"}),
            input_model=AuthInput,
            responses=[],
        ).model
    )
    tool_map = {m.name: tools.get(m.name) for m in tools.list()}
    model_map = {m.name: models.get(m.name) for m in models.list()}
    context, signals = validate_context(context)
    first = build_replanning_request(context, signals, tool_map, model_map)
    second = build_replanning_request(
        context,
        signals,
        dict(reversed(list(tool_map.items()))),
        dict(reversed(list(model_map.items()))),
    )
    assert first == second
    data = json.loads(first.user_prompt)
    assert [m["name"] for m in data["AVAILABLE READ-ONLY TOOLS"]] == ["aaa_lookup", "ioc_lookup"]
    assert [m["name"] for m in data["AVAILABLE SECURITY AI"]] == ["aaa_model", "auth_anomaly"]


@pytest.mark.parametrize("kind", ["tool", "ai"])
@pytest.mark.asyncio
async def test_fixed_registry_snapshot(
    kind: str,
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
    mock_tool: MockTool,
    mock_ai: MockSecurityAI,
) -> None:
    class RegisteringClient(MockLLMClient):
        async def generate_structured[T: BaseModel](
            self, *, request: LLMRequest, response_model: type[T]
        ) -> T:
            if kind == "tool":
                tools.register(
                    MockTool(
                        metadata=mock_tool.tool.metadata.model_copy(update={"name": "late_tool"}),
                        input_model=LookupInput,
                        output_model=LookupOutput,
                        responses=[],
                    ).tool
                )
            else:
                models.register(
                    MockSecurityAI(
                        metadata=mock_ai.model.metadata.model_copy(update={"name": "late_ai"}),
                        input_model=AuthInput,
                        responses=[],
                    ).model
                )
            return await super().generate_structured(request=request, response_model=response_model)

    client = RegisteringClient([response(f"continue_with_{kind}", name=f"late_{kind}")])
    with pytest.raises(UnknownPlannedToolError if kind == "tool" else UnknownSelectedModelError):
        await planner(client, tools, models).replan(context)
    assert f"late_{kind}" not in client.requests[0].user_prompt


@pytest.mark.asyncio
async def test_pending_tool_is_also_reserved(
    context: InvestigationContext, tools: ToolRegistry, models: SecurityAIRegistry
) -> None:
    from soc_agent.adaptive import RepeatedInvestigationError

    history = tool_history(context, tools, "pending")
    context = context.model_copy(update={"tool_history": (history,)})
    with pytest.raises(RepeatedInvestigationError):
        await planner(MockLLMClient([response("continue_with_tool")]), tools, models).replan(
            context
        )


@pytest.mark.asyncio
async def test_failed_ai_history_is_sufficient_replanning_context(
    context: InvestigationContext, tools: ToolRegistry, models: SecurityAIRegistry
) -> None:
    from soc_agent.state import IncidentState

    history = ai_history(context, models)
    context = InvestigationContext(
        incident=IncidentState(incident_id=context.incident.incident_id), ai_history=(history,)
    )
    result = await planner(MockLLMClient([response("escalate_to_human")]), tools, models).replan(
        context
    )
    assert result.decision.value == "escalate_to_human"


@pytest.mark.parametrize("kind", ["time", "incident", "count", "budget"])
@pytest.mark.asyncio
async def test_result_rejects_invalid_snapshots(
    kind: str, context: InvestigationContext, tools: ToolRegistry, models: SecurityAIRegistry
) -> None:
    from uuid import uuid4

    result = await planner(MockLLMClient([response("continue_with_ai")]), tools, models).replan(
        context
    )
    data = result.model_dump()
    if kind == "time":
        data["created_at"] = datetime(2026, 1, 1)
    elif kind == "incident":
        data["incident_id"] = uuid4()
    elif kind == "count":
        data["next_ai_plan"]["steps"] *= 2
    else:
        data["budget"]["current_round"] = 5
    with pytest.raises(ValidationError):
        AdaptiveInvestigationDecision.model_validate(data)


@pytest.mark.asyncio
async def test_terminal_decision_does_not_invoke_assessment_or_approval(
    context: InvestigationContext,
    tools: ToolRegistry,
    models: SecurityAIRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soc_agent.approval import ApprovalManager
    from soc_agent.assessment import ThreatAssessor
    from soc_agent.investigation import InvestigationOrchestrator
    from soc_agent.security_ai import SecurityAIInvestigator

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Replanner invoked an execution/assessment/approval service")

    monkeypatch.setattr(ThreatAssessor, "assess", forbidden)
    monkeypatch.setattr(ApprovalManager, "create", forbidden)
    monkeypatch.setattr(SecurityAIInvestigator, "execute", forbidden)
    monkeypatch.setattr(InvestigationOrchestrator, "execute_plan", forbidden)
    for choice in (
        "ready_for_assessment",
        "escalate_to_human",
        "continue_with_tool",
        "continue_with_ai",
    ):
        await planner(MockLLMClient([response(choice)]), tools, models).replan(context)
