from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.investigation import (
    InvestigationPlan,
    InvestigationStep,
    InvestigationStepStateError,
    InvestigationStepStatus,
)


def test_plan_defaults_and_serialization(plan: InvestigationPlan) -> None:
    assert plan.created_at.utcoffset() == timedelta(0)
    assert plan.plan_id.version == 4
    assert plan.steps[0].status is InvestigationStepStatus.PENDING
    assert InvestigationPlan.model_validate_json(plan.model_dump_json()) == plan
    with pytest.raises(ValidationError):
        plan.steps = ()


@pytest.mark.parametrize(
    "update",
    [
        {"purpose": " "},
        {"tool_name": " "},
        {"extra": 1},
        {"status": "completed"},
        {"status": "failed"},
        {"tool_input": []},
    ],
)
def test_invalid_step(plan: InvestigationPlan, update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        InvestigationStep.model_validate(plan.steps[0].model_dump() | update)


@pytest.mark.parametrize(
    "update", [{"steps": []}, {"created_at": datetime(2026, 1, 1)}, {"extra": True}]
)
def test_invalid_plan(plan: InvestigationPlan, update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        InvestigationPlan.model_validate(plan.model_dump() | update)


@pytest.mark.parametrize("identity", ["step_id", "action_id"])
def test_duplicate_ids(plan: InvestigationPlan, identity: str) -> None:
    first = plan.steps[0]
    second = InvestigationStep(tool_name="other", tool_input={}, purpose="Inspect")
    second = InvestigationStep.model_validate(
        second.model_dump() | {identity: getattr(first, identity)}
    )
    with pytest.raises(ValidationError):
        InvestigationPlan(incident_id=plan.incident_id, steps=(first, second))


def test_nested_inputs_and_transition(plan: InvestigationPlan) -> None:
    raw = {"nested": ["a"]}
    step = InvestigationStep(tool_name="test", tool_input=raw, purpose="Inspect")
    raw["nested"].append("b")
    assert step.tool_input == '{"nested":["a"]}'
    running = step.transition(InvestigationStepStatus.RUNNING)
    completed = running.transition(InvestigationStepStatus.COMPLETED, evidence_id=uuid4())
    assert completed.action_id == step.action_id
    assert step.status is InvestigationStepStatus.PENDING
    for status in (InvestigationStepStatus.PENDING, InvestigationStepStatus.RUNNING):
        with pytest.raises(InvestigationStepStateError):
            completed.transition(status)
