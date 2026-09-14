import pytest
from pydantic import BaseModel, JsonValue

from soc_agent.llm import LLMRequest, LLMResponseValidationError, MockLLMClient
from soc_agent.planning import InvestigationPlanner, PlanningError, UnknownPlannedToolError
from soc_agent.state import IncidentState
from soc_agent.tools import MockTool, Tool, ToolRegistry


@pytest.mark.asyncio
async def test_success_no_execution(
    response: dict[str, JsonValue], registry: ToolRegistry, mock_tool: MockTool
) -> None:
    llm = MockLLMClient([response])
    state = IncidentState()
    plan = await InvestigationPlanner(llm_client=llm, registry=registry).create_plan(state)
    assert plan.incident_id == state.incident_id
    assert len(plan.steps) == 1
    assert llm.call_count == 1
    assert mock_tool.call_count == 0
    assert state.evidence == ()


@pytest.mark.asyncio
async def test_empty_registry_skips_llm() -> None:
    llm = MockLLMClient([])
    with pytest.raises(PlanningError):
        await InvestigationPlanner(llm_client=llm, registry=ToolRegistry()).create_plan(
            IncidentState()
        )
    assert llm.call_count == 0


@pytest.mark.parametrize("kind", ["too_many", "authority"])
@pytest.mark.asyncio
async def test_invalid_llm_response_no_retry(
    response: dict[str, JsonValue], registry: ToolRegistry, mock_tool: MockTool, kind: str
) -> None:
    invalid = response | (
        {"steps": response["steps"] * 9} if kind == "too_many" else {"incident_id": "forged"}
    )
    llm = MockLLMClient([invalid, response])
    with pytest.raises(LLMResponseValidationError):
        await InvestigationPlanner(llm_client=llm, registry=registry).create_plan(IncidentState())
    assert llm.call_count == 1
    assert mock_tool.call_count == 0


@pytest.mark.asyncio
async def test_catalog_snapshot_rejects_late_registration(
    response: dict[str, JsonValue], registry: ToolRegistry, mock_tool: MockTool
) -> None:
    late = Tool(
        mock_tool.tool.metadata.model_copy(update={"name": "late_tool"}),
        mock_tool.tool.input_model,
        mock_tool.tool.output_model,
        mock_tool.tool.handler,
    )

    class RegisteringLLM(MockLLMClient):
        async def generate_structured[T: BaseModel](
            self, *, request: LLMRequest, response_model: type[T]
        ) -> T:
            registry.register(late)
            return await super().generate_structured(request=request, response_model=response_model)

    payload = response | {"steps": [response["steps"][0] | {"tool_name": "late_tool"}]}
    llm = RegisteringLLM([payload])
    with pytest.raises(UnknownPlannedToolError):
        await InvestigationPlanner(llm_client=llm, registry=registry).create_plan(IncidentState())
    assert "late_tool" not in llm.requests[0].user_prompt
    assert mock_tool.call_count == 0
