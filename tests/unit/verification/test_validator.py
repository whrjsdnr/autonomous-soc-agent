from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.response import ResponsePlan, ResponseStep
from soc_agent.state import Evidence, IncidentState
from soc_agent.verification import (
    InvalidVerificationEvidenceError,
    VerificationBindingError,
    VerificationPlan,
    VerificationResult,
)
from soc_agent.verification.validator import validate_collection

from .conftest import Context


@pytest.mark.parametrize("field", ["response_plan_id", "response_step_id", "assessment_id"])
def test_wrong_target(context: Context, plan: VerificationPlan, field: str) -> None:
    changed = VerificationPlan.model_validate(plan.model_dump() | {field: uuid4()})
    with pytest.raises(VerificationBindingError):
        validate_collection(context.state, changed, context.response)


def test_same_ids_changed_input_rejected(context: Context, plan: VerificationPlan) -> None:
    step = ResponseStep.model_validate(
        context.response.steps[0].model_dump()
        | {
            "tool_input": {"ip": "different"},
        }
    )
    response = ResponsePlan.model_validate(context.response.model_dump() | {"steps": (step,)})
    with pytest.raises(VerificationBindingError):
        validate_collection(context.state, plan, response)


def test_baseline_cannot_be_relabelled(context: Context, collected: VerificationResult) -> None:
    changed = collected.plan.steps[0].model_dump() | {
        "evidence_id": context.state.evidence[0].evidence_id
    }
    with pytest.raises(ValidationError, match="Baseline"):
        VerificationPlan.model_validate(collected.plan.model_dump() | {"steps": (changed,)})


@pytest.mark.parametrize("kind", ["missing", "tool", "source", "time"])
def test_provenance_revalidated(context: Context, collected: VerificationResult, kind: str) -> None:
    record = collected.incident_state.evidence[-1]
    if kind == "missing":
        state = context.state
    else:
        update = (
            {"tool_name": "other"}
            if kind == "tool"
            else {"source": "manual"}
            if kind == "source"
            else {
                "collected_at": collected.plan.created_at - timedelta(seconds=1),
            }
        )
        changed = Evidence.model_validate(record.model_dump() | update)
        state = IncidentState.model_validate(
            collected.incident_state.model_dump()
            | {
                "evidence": (*context.state.evidence, changed),
            }
        )
    with pytest.raises(InvalidVerificationEvidenceError):
        validate_collection(state, collected.plan, context.response)


def test_evidence_from_other_verification_not_valid_reference(
    context: Context,
    collected: VerificationResult,
) -> None:
    from soc_agent.verification import VerificationAssessmentDraft, VerificationStepStatus
    from soc_agent.verification.validator import convert_assessment

    # Another read can exist in the incident, but is not one of this plan's collections.
    extra = Evidence.model_validate(
        collected.incident_state.evidence[-1].model_dump()
        | {
            "evidence_id": uuid4(),
        }
    )
    other_state = collected.incident_state.add_evidence(extra)
    result = VerificationResult(incident_state=other_state, plan=collected.plan)
    assert result.plan.steps[0].status is VerificationStepStatus.COMPLETED
    with pytest.raises(InvalidVerificationEvidenceError):
        convert_assessment(
            VerificationAssessmentDraft(
                outcome="verified",
                confidence=1.0,
                summary="Other collection cannot be cited",
                supporting_evidence_ids=(extra.evidence_id,),
            ),
            result,
        )
