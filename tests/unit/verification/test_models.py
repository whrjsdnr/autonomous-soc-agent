from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import JsonValue, ValidationError

from soc_agent.verification import (
    VerificationAssessmentDraft,
    VerificationOutcome,
    VerificationPlan,
    VerificationPlanDraft,
    VerificationStep,
    VerificationStepDraft,
    VerificationStepStateError,
    VerificationStepStatus,
)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tool_name", " "),
        ("purpose", " "),
        ("expected_signal", " "),
        ("tool_input", []),
        ("tool_input", {"x": object()}),
        ("tool_input", {"x": float("nan")}),
        ("action_id", "forged"),
        ("verification_action_id", "forged"),
        ("step_id", "forged"),
        ("status", "completed"),
        ("risk_level", "low"),
        ("permission", "network_read"),
        ("approval_id", "forged"),
    ],
)
def test_invalid_step_draft(draft_payload: dict[str, JsonValue], field: str, value: object) -> None:
    step = VerificationPlanDraft.model_validate(draft_payload).steps[0]
    with pytest.raises(ValidationError):
        VerificationStepDraft.model_validate(step.model_dump() | {field: value})


@pytest.mark.parametrize("count", [0, 6])
def test_count_limit(draft_payload: dict[str, JsonValue], count: int) -> None:
    draft = VerificationPlanDraft.model_validate(draft_payload)
    with pytest.raises(ValidationError):
        VerificationPlanDraft.model_validate(draft.model_dump() | {"steps": draft.steps * count})


@pytest.mark.parametrize("field", ["verification_plan_id", "incident_id", "target_action_id"])
def test_no_draft_identity(draft_payload: dict[str, JsonValue], field: str) -> None:
    with pytest.raises(ValidationError):
        VerificationPlanDraft.model_validate(draft_payload | {field: str(uuid4())})


def test_immutable_roundtrip_and_transitions(plan: VerificationPlan) -> None:
    assert VerificationPlan.model_validate_json(plan.model_dump_json()) == plan
    assert plan.created_at.utcoffset().total_seconds() == 0
    with pytest.raises(ValidationError):
        plan.goal = "changed"
    with pytest.raises(ValidationError):
        VerificationPlan.model_validate(plan.model_dump() | {"created_at": datetime(2026, 1, 1)})
    step = plan.steps[0]
    with pytest.raises(VerificationStepStateError):
        step.transition(VerificationStepStatus.COMPLETED)
    completed = step.transition(VerificationStepStatus.RUNNING).transition(
        VerificationStepStatus.COMPLETED,
        evidence_id=uuid4(),
    )
    assert completed.verification_action_id == step.verification_action_id
    with pytest.raises(VerificationStepStateError):
        completed.transition(VerificationStepStatus.RUNNING)
    with pytest.raises(ValidationError):
        step.transition(VerificationStepStatus.RUNNING).transition(VerificationStepStatus.FAILED)
    raw = {"nested": [1]}
    snapshot = VerificationStep.model_validate(step.model_dump() | {"tool_input": raw})
    raw["nested"].append(2)
    assert snapshot.tool_input == '{"nested":[1]}'


@pytest.mark.parametrize("field", ["step_id", "verification_action_id"])
def test_unique_step_ids(plan: VerificationPlan, field: str) -> None:
    first = plan.steps[0]
    second = VerificationStep.model_validate(
        first.model_dump()
        | {
            "step_id": uuid4(),
            "verification_action_id": uuid4(),
            field: getattr(first, field),
        }
    )
    with pytest.raises(ValidationError):
        VerificationPlan.model_validate(plan.model_dump() | {"steps": (first, second)})


@pytest.mark.parametrize("outcome", list(VerificationOutcome))
def test_outcome_independent_confidence(outcome: VerificationOutcome) -> None:
    draft = VerificationAssessmentDraft(
        outcome=outcome, confidence=0.95, summary="Fixture", supporting_evidence_ids=(uuid4(),)
    )
    assert draft.outcome == outcome


@pytest.mark.parametrize(
    "update",
    [
        {"confidence": -0.1},
        {"confidence": 1.1},
        {"confidence": float("nan")},
        {"supporting_evidence_ids": []},
        {"outcome": "resolved"},
        {"summary": " "},
        {"verification_id": "fake"},
        {"incident_id": "fake"},
        {"response_plan_id": "fake"},
        {"response_step_id": "fake"},
        {"target_action_id": "fake"},
        {"created_at": "fake"},
        {"new_response": "disable_account"},
    ],
)
def test_invalid_assessment_draft(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        VerificationAssessmentDraft.model_validate(
            {
                "outcome": "verified",
                "confidence": 0.9,
                "summary": "Fixture",
                "supporting_evidence_ids": [uuid4()],
            }
            | update
        )
