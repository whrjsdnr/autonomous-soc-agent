from datetime import datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from soc_agent.response import (
    ResponsePlan,
    ResponsePlanDraft,
    ResponseStep,
    ResponseStepDraft,
    ResponseStepStateError,
    ResponseStepStatus,
)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tool_name", " "),
        ("purpose", " "),
        ("tool_input", []),
        ("tool_input", {"bad": object()}),
        ("tool_input", {"bad": float("nan")}),
        ("action_id", str(uuid4())),
        ("approval_id", str(uuid4())),
        ("risk_level", "low"),
        ("permission", "network_read"),
        ("status", "completed"),
        ("policy_decision", "allow"),
    ],
)
def test_untrusted_step_rejected(payload, field, value):
    with pytest.raises(ValidationError):
        ResponseStepDraft.model_validate(payload["steps"][0] | {field: value})


@pytest.mark.parametrize("count", [0, 6])
def test_bounded_plan(payload, count):
    with pytest.raises(ValidationError):
        ResponsePlanDraft.model_validate(payload | {"steps": payload["steps"] * count})


def test_draft_and_domain_identity(context, payload):
    state, assessment = context
    draft = ResponsePlanDraft.model_validate(payload)
    raw = {"nested": {"list": [1, 2]}}
    step = ResponseStep(tool_name="block_ip", tool_input=raw, purpose=draft.steps[0].purpose)
    raw["nested"]["list"].append(3)
    assert step.tool_input == '{"nested":{"list":[1,2]}}'
    plan = ResponsePlan(
        incident_id=state.incident_id,
        assessment_id=assessment.assessment_id,
        goal=draft.goal,
        steps=(step,),
    )
    assert isinstance(step.action_id, UUID)
    assert plan.created_at.utcoffset().total_seconds() == 0
    assert step.status is ResponseStepStatus.PENDING
    with pytest.raises(ValidationError):
        step.tool_input = "{}"
    with pytest.raises(ValidationError):
        plan.goal = "changed"
    with pytest.raises(ValidationError):
        ResponsePlan.model_validate(plan.model_dump() | {"created_at": datetime(2026, 1, 1)})
    with pytest.raises(ValidationError):
        ResponsePlan.model_validate(plan.model_dump() | {"approval": True})
    other = ResponseStep(tool_name="block_ip", tool_input={}, purpose="Other")
    assert other.action_id != step.action_id and other.step_id != step.step_id
    for key in ("step_id", "action_id"):
        duplicate = ResponseStep.model_validate(other.model_dump() | {key: getattr(step, key)})
        with pytest.raises(ValidationError):
            ResponsePlan.model_validate(plan.model_dump() | {"steps": (step, duplicate)})


def test_transitions(payload):
    step = ResponseStep(**payload["steps"][0])
    with pytest.raises(ResponseStepStateError):
        step.transition(ResponseStepStatus.COMPLETED)
    done = step.transition(ResponseStepStatus.EXECUTING).transition(ResponseStepStatus.COMPLETED)
    assert step.status is ResponseStepStatus.PENDING
    assert done.action_id == step.action_id
    with pytest.raises(ResponseStepStateError):
        done.transition(ResponseStepStatus.PENDING)
    with pytest.raises(ValidationError):
        step.transition(ResponseStepStatus.EXECUTING).transition(ResponseStepStatus.FAILED)


@pytest.mark.parametrize("field", ["plan_id", "incident_id", "assessment_id", "created_at"])
def test_draft_rejects_application_fields(payload, field: str) -> None:
    with pytest.raises(ValidationError):
        ResponsePlanDraft.model_validate(payload | {field: str(uuid4())})


def test_result_incident_binding_and_roundtrip(context, payload) -> None:
    from soc_agent.response import ResponseResult
    from soc_agent.state import IncidentState

    state, assessment = context
    plan = ResponsePlan(
        incident_id=state.incident_id,
        assessment_id=assessment.assessment_id,
        goal=payload["goal"],
        steps=(ResponseStep(**payload["steps"][0]),),
    )
    result = ResponseResult(incident_state=state, plan=plan)
    assert ResponseResult.model_validate_json(result.model_dump_json()) == result
    with pytest.raises(ValidationError, match="incident IDs"):
        ResponseResult(incident_state=IncidentState(), plan=plan)
