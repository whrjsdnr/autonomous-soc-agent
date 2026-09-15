from uuid import uuid4

import pytest
from pydantic import JsonValue

from soc_agent.llm import LLMResponseValidationError, MockLLMClient
from soc_agent.response import ResponsePlan, ResponseStep, ResponseStepStatus, StepFailure
from soc_agent.tools import ToolPermission, ToolRiskLevel
from soc_agent.verification import (
    VerificationBindingError,
    VerificationPlanner,
    VerificationPlanningError,
)

from .conftest import Context, Runtime, make_tool


@pytest.mark.asyncio
async def test_plan_only(
    context: Context, runtime: Runtime, draft_payload: dict[str, JsonValue]
) -> None:
    llm = MockLLMClient([draft_payload])
    before = context.state.model_dump_json(), context.assessment.model_dump_json()
    plan = await VerificationPlanner(llm_client=llm, registry=runtime.registry).create_plan(
        incident_state=context.state,
        threat_assessment=context.assessment,
        response_plan=context.response,
        response_step_id=context.response.steps[0].step_id,
    )
    assert plan.target_action_id == context.response.steps[0].action_id
    assert plan.response_plan_id == context.response.plan_id
    assert plan.assessment_id == context.assessment.assessment_id
    assert plan.steps[0].verification_action_id != plan.target_action_id
    assert plan.steps[0].verification_action_id.version == 4
    assert plan.steps[0].tool_input == '{"ip":"203.0.113.20","window_seconds":300}'
    assert runtime.mock.call_count == 0 and llm.call_count == 1
    assert before == (context.state.model_dump_json(), context.assessment.model_dump_json())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [
        ResponseStepStatus.PENDING,
        ResponseStepStatus.EXECUTING,
        ResponseStepStatus.BLOCKED,
        ResponseStepStatus.FAILED,
    ],
)
async def test_noncompleted_rejected(
    context: Context, runtime: Runtime, status: ResponseStepStatus
) -> None:
    data = context.response.steps[0].model_dump() | {"status": status}
    if status in (ResponseStepStatus.BLOCKED, ResponseStepStatus.FAILED):
        data["failure"] = StepFailure(error_type="Fixture", reason="Not completed")
    response = ResponsePlan.model_validate(
        context.response.model_dump()
        | {
            "steps": (ResponseStep.model_validate(data),),
        }
    )
    llm = MockLLMClient([])
    with pytest.raises(VerificationBindingError):
        await VerificationPlanner(llm_client=llm, registry=runtime.registry).create_plan(
            incident_state=context.state,
            threat_assessment=context.assessment,
            response_plan=response,
            response_step_id=response.steps[0].step_id,
        )
    assert llm.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["incident_id", "assessment_id"])
async def test_cross_binding(context: Context, runtime: Runtime, field: str) -> None:
    response = ResponsePlan.model_validate(context.response.model_dump() | {field: uuid4()})
    llm = MockLLMClient([])
    with pytest.raises(VerificationBindingError):
        await VerificationPlanner(llm_client=llm, registry=runtime.registry).create_plan(
            incident_state=context.state,
            threat_assessment=context.assessment,
            response_plan=response,
            response_step_id=response.steps[0].step_id,
        )
    assert llm.call_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["unknown", "write", "high", "destructive", "input", "count"])
async def test_invalid_proposal(context: Context, runtime: Runtime, kind: str) -> None:
    name = "search_auth_logs_after_action"
    if kind in ("write", "high", "destructive"):
        name = "forbidden_tool"
        mock = make_tool(
            name=name,
            permission=ToolPermission.NETWORK_WRITE
            if kind == "write"
            else ToolPermission.NETWORK_READ,
            risk=ToolRiskLevel.HIGH
            if kind == "high"
            else ToolRiskLevel.DESTRUCTIVE
            if kind == "destructive"
            else ToolRiskLevel.LOW,
        )
        runtime.registry.register(mock.tool)
    elif kind == "unknown":
        name = "verify_everything_magically"
    step: JsonValue = {
        "tool_name": name,
        "purpose": "Check",
        "expected_signal": "No attempts",
        "tool_input": {"ip_address": 123} if kind == "input" else {"ip": "x"},
    }
    llm = MockLLMClient([{"goal": "Check", "steps": [step] * (6 if kind == "count" else 1)}])
    with pytest.raises(
        LLMResponseValidationError if kind == "count" else VerificationPlanningError
    ):
        await VerificationPlanner(llm_client=llm, registry=runtime.registry).create_plan(
            incident_state=context.state,
            threat_assessment=context.assessment,
            response_plan=context.response,
            response_step_id=context.response.steps[0].step_id,
        )
    assert llm.call_count == 1 and runtime.mock.call_count == 0
    assert "forbidden_tool" not in llm.requests[0].user_prompt


@pytest.mark.asyncio
async def test_empty_read_catalog_skips_llm(context: Context) -> None:
    from soc_agent.tools import ToolRegistry

    registry = ToolRegistry()
    registry.register(make_tool(permission=ToolPermission.NETWORK_WRITE).tool)
    llm = MockLLMClient([])
    with pytest.raises(VerificationPlanningError):
        await VerificationPlanner(llm_client=llm, registry=registry).create_plan(
            incident_state=context.state,
            threat_assessment=context.assessment,
            response_plan=context.response,
            response_step_id=context.response.steps[0].step_id,
        )
    assert llm.call_count == 0


@pytest.mark.asyncio
async def test_late_registration_not_in_snapshot(context: Context, runtime: Runtime) -> None:
    from pydantic import BaseModel

    from soc_agent.llm import LLMRequest

    late = make_tool(name="late_read_tool")

    class RegisteringLLM(MockLLMClient):
        async def generate_structured[T: BaseModel](
            self,
            *,
            request: LLMRequest,
            response_model: type[T],
        ) -> T:
            runtime.registry.register(late.tool)
            return await super().generate_structured(request=request, response_model=response_model)

    llm = RegisteringLLM(
        [
            {
                "goal": "Check",
                "steps": [
                    {
                        "tool_name": "late_read_tool",
                        "tool_input": {"ip": "x"},
                        "purpose": "Read",
                        "expected_signal": "No attempts",
                    }
                ],
            }
        ]
    )
    with pytest.raises(VerificationPlanningError):
        await VerificationPlanner(llm_client=llm, registry=runtime.registry).create_plan(
            incident_state=context.state,
            threat_assessment=context.assessment,
            response_plan=context.response,
            response_step_id=context.response.steps[0].step_id,
        )
    assert late.call_count == 0 and llm.call_count == 1
