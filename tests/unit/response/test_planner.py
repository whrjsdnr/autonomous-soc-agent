from uuid import uuid4

import pytest

from soc_agent.assessment import ThreatAssessment
from soc_agent.llm import LLMResponseValidationError, MockLLMClient
from soc_agent.response import (
    InvalidResponseReferenceError,
    ResponsePlanMismatchError,
    ResponsePlanner,
    ResponsePlanningError,
    ResponseStepStatus,
)
from soc_agent.tools import ToolRegistry, ToolRiskLevel


@pytest.mark.asyncio
@pytest.mark.parametrize("risk", list(ToolRiskLevel))
async def test_planner_only_proposes(context, payload, setup_tools, risk):
    state, assessment = context
    mock, registry, *_ = setup_tools(risk)
    llm = MockLLMClient([payload, payload])
    planner = ResponsePlanner(llm_client=llm, registry=registry)
    plans = [
        await planner.create_plan(incident_state=state, threat_assessment=assessment)
        for _ in range(2)
    ]
    for plan in plans:
        assert plan.incident_id == state.incident_id
        assert plan.assessment_id == assessment.assessment_id
        assert plan.steps[0].status is ResponseStepStatus.PENDING
        assert plan.steps[0].tool_input == '{"ip":"203.0.113.20"}'
    assert plans[0].plan_id != plans[1].plan_id
    assert plans[0].steps[0].step_id != plans[1].steps[0].step_id
    assert plans[0].steps[0].action_id != plans[1].steps[0].action_id
    assert llm.call_count == 2 and mock.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"tool_name": "shutdown_datacenter"},
        {"tool_input": {"ip_address": 123}},
        {"tool_input": {"ip": 123}},
        {"tool_input": {"ip": "x", "extra": True}},
    ],
)
async def test_invalid_tool_proposal(context, payload, setup_tools, changes):
    state, assessment = context
    mock, registry, *_ = setup_tools()
    payload["steps"][0].update(changes)
    llm = MockLLMClient([payload])
    with pytest.raises(ResponsePlanningError):
        await ResponsePlanner(llm_client=llm, registry=registry).create_plan(
            incident_state=state, threat_assessment=assessment
        )
    assert llm.call_count == 1 and mock.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "supporting_evidence_ids",
        "supporting_observation_ids",
        "supporting_hypothesis_ids",
        "incident_id",
    ],
)
async def test_broken_provenance_before_llm(context, payload, setup_tools, field):
    state, assessment = context
    _, registry, *_ = setup_tools()
    changed = uuid4() if field == "incident_id" else (uuid4(),)
    assessment = ThreatAssessment.model_validate(assessment.model_dump() | {field: changed})
    llm = MockLLMClient([payload])
    error = ResponsePlanMismatchError if field == "incident_id" else InvalidResponseReferenceError
    with pytest.raises(error):
        await ResponsePlanner(llm_client=llm, registry=registry).create_plan(
            incident_state=state, threat_assessment=assessment
        )
    assert llm.call_count == 0


@pytest.mark.asyncio
async def test_empty_catalog(context, payload):
    llm = MockLLMClient([payload])
    with pytest.raises(ResponsePlanningError):
        await ResponsePlanner(llm_client=llm, registry=ToolRegistry()).create_plan(
            incident_state=context[0], threat_assessment=context[1]
        )
    assert llm.call_count == 0


@pytest.mark.asyncio
async def test_llm_error_no_retry(context, payload, setup_tools):
    payload["steps"] *= 6
    llm = MockLLMClient([payload])
    with pytest.raises(LLMResponseValidationError):
        await ResponsePlanner(llm_client=llm, registry=setup_tools()[1]).create_plan(
            incident_state=context[0], threat_assessment=context[1]
        )
    assert llm.call_count == 1


@pytest.mark.asyncio
async def test_catalog_snapshot_excludes_late_tool(context, payload, setup_tools) -> None:
    from pydantic import BaseModel

    from soc_agent.llm import LLMRequest
    from soc_agent.tools import Tool, ToolMetadata

    mock, registry, *_ = setup_tools()
    late = Tool(
        ToolMetadata.model_validate(mock.tool.metadata.model_dump() | {"name": "late_tool"}),
        mock.tool.input_model,
        mock.tool.output_model,
        mock.tool.handler,
    )

    class RegisteringLLM(MockLLMClient):
        async def generate_structured[T: BaseModel](
            self, *, request: LLMRequest, response_model: type[T]
        ) -> T:
            registry.register(late)
            return await super().generate_structured(request=request, response_model=response_model)

    payload["steps"][0]["tool_name"] = "late_tool"
    llm = RegisteringLLM([payload])
    with pytest.raises(ResponsePlanningError):
        await ResponsePlanner(llm_client=llm, registry=registry).create_plan(
            incident_state=context[0], threat_assessment=context[1]
        )
    assert "late_tool" not in llm.requests[0].user_prompt
    assert mock.call_count == 0


@pytest.mark.asyncio
async def test_oversized_context_skips_llm(context, setup_tools) -> None:
    from soc_agent.state import Evidence, IncidentState

    state, assessment = context
    evidence = Evidence.model_validate(state.evidence[0].model_dump() | {"summary": "x" * 64000})
    state = IncidentState.model_validate(state.model_dump() | {"evidence": (evidence,)})
    llm = MockLLMClient([])
    with pytest.raises(ResponsePlanningError, match="64000"):
        await ResponsePlanner(llm_client=llm, registry=setup_tools()[1]).create_plan(
            incident_state=state, threat_assessment=assessment
        )
    assert llm.call_count == 0
