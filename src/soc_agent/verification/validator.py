"""Deterministic target, capability, schema, and post-action reference validation."""

from collections.abc import Mapping
from uuid import UUID

from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticSerializationError

from soc_agent.assessment import AssessmentResult, ThreatAssessment
from soc_agent.execution import ActionProposal
from soc_agent.response import ResponsePlan, ResponseStep, ResponseStepStatus
from soc_agent.state import IncidentState
from soc_agent.tools import Tool
from soc_agent.verification.errors import (
    InvalidVerificationDraftError,
    InvalidVerificationEvidenceError,
    NoVerificationEvidenceError,
    VerificationBindingError,
    VerificationPlanningError,
)
from soc_agent.verification.models import (
    VerificationAssessment,
    VerificationAssessmentDraft,
    VerificationPlan,
    VerificationPlanDraft,
    VerificationResult,
    VerificationStep,
)


def completed_target(state: IncidentState, response: ResponsePlan, step_id: UUID) -> ResponseStep:
    if state.incident_id != response.incident_id:
        raise VerificationBindingError("Response belongs to another incident")
    step = next((s for s in response.steps if s.step_id == step_id), None)
    if step is None or step.status != ResponseStepStatus.COMPLETED:
        raise VerificationBindingError("Verification requires an existing completed response step")
    return step


def validate_target(
    state: IncidentState,
    assessment: ThreatAssessment,
    response: ResponsePlan,
    step_id: UUID,
) -> tuple[IncidentState, ThreatAssessment, ResponsePlan]:
    try:
        context = AssessmentResult.model_validate(
            {
                "incident_state": state.model_dump(warnings=False),
                "threat_assessment": assessment.model_dump(warnings=False),
            }
        )
        response = ResponsePlan.model_validate(response.model_dump(warnings=False))
    except ValidationError as error:
        raise VerificationBindingError(
            "Invalid incident, assessment, or response snapshot"
        ) from error
    if response.assessment_id != context.threat_assessment.assessment_id:
        raise VerificationBindingError("Response references a different threat assessment")
    completed_target(context.incident_state, response, step_id)
    return context.incident_state, context.threat_assessment, response


def target_action(response: ResponsePlan, step: ResponseStep) -> ActionProposal:
    return ActionProposal(
        action_id=step.action_id,
        incident_id=response.incident_id,
        tool_name=step.tool_name,
        tool_input=step.tool_input,
        created_at=response.created_at,
    )


def normalize_plan(
    draft: VerificationPlanDraft,
    *,
    state: IncidentState,
    assessment: ThreatAssessment,
    response: ResponsePlan,
    response_step_id: UUID,
    tools: Mapping[str, Tool[BaseModel, BaseModel]],
) -> VerificationPlan:
    state, assessment, response = validate_target(state, assessment, response, response_step_id)
    target = completed_target(state, response, response_step_id)
    try:
        draft = VerificationPlanDraft.model_validate(draft.model_dump(warnings=False))
    except ValidationError as error:
        raise VerificationPlanningError("Invalid verification plan draft") from error
    steps = []
    for step in draft.steps:
        tool = tools.get(step.tool_name)
        if tool is None or not tool.metadata.is_read_only_capability:
            raise VerificationPlanningError("Tool is outside the observation-only catalog")
        try:
            value = tool.input_model.model_validate(step.tool_input, extra="forbid")
            payload = value.model_dump(mode="json", by_alias=True, round_trip=True)
            canonical = ActionProposal.canonical_input(payload)
            tool.input_model.model_validate(payload, extra="forbid")
        except (ValueError, TypeError, PydanticSerializationError) as error:
            raise VerificationPlanningError("Invalid verification tool input") from error
        steps.append(
            VerificationStep(
                tool_name=step.tool_name,
                tool_input=canonical,
                purpose=step.purpose,
                expected_signal=step.expected_signal,
            )
        )
    return VerificationPlan(
        incident_id=state.incident_id,
        assessment_id=assessment.assessment_id,
        response_plan_id=response.plan_id,
        response_step_id=target.step_id,
        target_action=target_action(response, target),
        target_purpose=target.purpose,
        baseline_evidence_ids=tuple(e.evidence_id for e in state.evidence),
        goal=draft.goal,
        steps=tuple(steps),
    )


def validate_collection(
    state: IncidentState,
    plan: VerificationPlan,
    response: ResponsePlan,
) -> VerificationResult:
    try:
        response = ResponsePlan.model_validate(response.model_dump(warnings=False))
        result = VerificationResult.model_validate(
            {
                "incident_state": state.model_dump(warnings=False),
                "plan": plan.model_dump(warnings=False),
            }
        )
    except ValidationError as error:
        raise InvalidVerificationEvidenceError(
            "Invalid verification collection snapshot"
        ) from error
    plan = result.plan
    step = completed_target(result.incident_state, response, plan.response_step_id)
    if (
        plan.response_plan_id != response.plan_id
        or plan.assessment_id != response.assessment_id
        or plan.target_action != target_action(response, step)
        or plan.target_purpose != step.purpose
    ):
        raise VerificationBindingError("Verification does not match the exact completed response")
    return result


def convert_assessment(
    draft: VerificationAssessmentDraft,
    collection: VerificationResult,
) -> VerificationAssessment:
    """Atomic conversion: reference membership does not prove semantic entailment."""
    try:
        collection = VerificationResult.model_validate(collection.model_dump(warnings=False))
    except ValidationError as error:
        raise InvalidVerificationEvidenceError("Invalid collection provenance") from error
    plan = collection.plan
    if not plan.verification_evidence_ids:
        raise NoVerificationEvidenceError("No post-action verification evidence")
    try:
        draft = VerificationAssessmentDraft.model_validate(draft.model_dump(warnings=False))
    except ValidationError as error:
        raise InvalidVerificationDraftError("Invalid verification assessment draft") from error
    if not set(draft.supporting_evidence_ids) <= set(plan.verification_evidence_ids):
        raise InvalidVerificationEvidenceError("Only this plan's collected evidence may be cited")
    return VerificationAssessment(
        verification_plan_id=plan.verification_plan_id,
        incident_id=plan.incident_id,
        assessment_id=plan.assessment_id,
        response_plan_id=plan.response_plan_id,
        response_step_id=plan.response_step_id,
        target_action_id=plan.target_action_id,
        **draft.model_dump(),
    )
