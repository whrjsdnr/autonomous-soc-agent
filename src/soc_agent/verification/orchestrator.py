"""Sequential observation through governed execution, with immutable evidence append."""

from uuid import UUID

from soc_agent.approval import ApprovalError
from soc_agent.execution import ActionProposal, ExecutionError, GovernedExecutor
from soc_agent.investigation import EvidenceConversionError, StepFailure
from soc_agent.investigation.evidence import evidence_from_result
from soc_agent.response import ResponsePlan
from soc_agent.state import IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools import ToolError
from soc_agent.verification.errors import VerificationStepStateError
from soc_agent.verification.models import (
    VerificationPlan,
    VerificationResult,
    VerificationStepStatus,
)
from soc_agent.verification.validator import validate_collection


class VerificationOrchestrator:
    """No remediation, approval creation, retries, or outcome assessment.

    Reuses investigation's result adapter without sharing investigation lifecycle.
    Cancellation propagates; a single shared executor retains attempted action IDs.
    """

    def __init__(self, *, executor: GovernedExecutor) -> None:
        self._executor = executor

    def prepare_step(
        self,
        *,
        incident_state: IncidentState,
        response_plan: ResponsePlan,
        plan: VerificationPlan,
        step_id: UUID,
    ) -> ActionProposal:
        collection = validate_collection(incident_state, plan, response_plan)
        plan = collection.plan
        step = plan.get_step(step_id)
        if step.status not in (VerificationStepStatus.PENDING, VerificationStepStatus.BLOCKED):
            raise VerificationStepStateError("Only pending or blocked checks can be prepared")
        return ActionProposal(
            action_id=step.verification_action_id,
            incident_id=plan.incident_id,
            tool_name=step.tool_name,
            tool_input=step.tool_input,
            created_at=plan.created_at,
        )

    async def execute_step(
        self,
        *,
        incident_state: IncidentState,
        response_plan: ResponsePlan,
        plan: VerificationPlan,
        step_id: UUID,
    ) -> VerificationResult:
        collection = validate_collection(incident_state, plan, response_plan)
        state, plan = collection.incident_state, collection.plan
        action = self.prepare_step(
            incident_state=state,
            response_plan=response_plan,
            plan=plan,
            step_id=step_id,
        )
        running = plan.transition_step(step_id, VerificationStepStatus.RUNNING)
        try:
            result = await self._executor.execute(action, require_read_only=True)
        except (ExecutionError, ApprovalError) as error:
            return self._failure(state, running, step_id, VerificationStepStatus.BLOCKED, error)
        except ToolError as error:
            return self._failure(state, running, step_id, VerificationStepStatus.FAILED, error)
        try:
            evidence = evidence_from_result(
                result,
                incident_id=plan.incident_id,
                expected_tool_name=action.tool_name,
                observed_at=utc_now(),
            )
        except EvidenceConversionError as error:
            return self._failure(state, running, step_id, VerificationStepStatus.FAILED, error)
        updated = state.add_evidence(evidence)
        completed = running.transition_step(
            step_id,
            VerificationStepStatus.COMPLETED,
            evidence_id=evidence.evidence_id,
        )
        return VerificationResult(incident_state=updated, plan=completed)

    def _failure(
        self,
        state: IncidentState,
        plan: VerificationPlan,
        step_id: UUID,
        status: VerificationStepStatus,
        error: Exception,
    ) -> VerificationResult:
        return VerificationResult(
            incident_state=state,
            plan=plan.transition_step(
                step_id,
                status,
                failure=StepFailure(
                    error_type=type(error).__name__,
                    reason=str(error) or type(error).__name__,
                ),
            ),
        )

    async def execute_plan(
        self,
        *,
        incident_state: IncidentState,
        response_plan: ResponsePlan,
        plan: VerificationPlan,
    ) -> VerificationResult:
        result = validate_collection(incident_state, plan, response_plan)
        for step in result.plan.steps:
            if step.status == VerificationStepStatus.COMPLETED:
                continue
            if step.status in (VerificationStepStatus.BLOCKED, VerificationStepStatus.FAILED):
                break
            result = await self.execute_step(
                incident_state=result.incident_state,
                response_plan=response_plan,
                plan=result.plan,
                step_id=step.step_id,
            )
            if result.plan.get_step(step.step_id).status != VerificationStepStatus.COMPLETED:
                break
        return result
