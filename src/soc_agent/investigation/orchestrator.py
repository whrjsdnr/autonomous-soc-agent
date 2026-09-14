"""Bounded sequential investigation via the governed executor only."""

from collections.abc import Mapping
from uuid import UUID

from soc_agent.approval.errors import ApprovalError
from soc_agent.execution import ActionProposal, ExecutionError, GovernedExecutor
from soc_agent.investigation.errors import (
    EvidenceConversionError,
    InvestigationPlanMismatchError,
    InvestigationStepStateError,
)
from soc_agent.investigation.evidence import evidence_from_result
from soc_agent.investigation.models import (
    InvestigationPlan,
    InvestigationResult,
    InvestigationStepStatus,
    StepFailure,
)
from soc_agent.state import IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools import ToolError


class InvestigationOrchestrator:
    """No planning, authorization, automatic retries, or incident classification.

    Explicit execute_step may re-evaluate a BLOCKED step after human action;
    execute_plan stops on an existing block/failure until the caller resolves it.
    Cancellation propagates; durable recovery is not implemented.
    """

    def __init__(self, *, executor: GovernedExecutor) -> None:
        self._executor = executor

    def _check_incident(self, incident_state: IncidentState, plan: InvestigationPlan) -> None:
        if incident_state.incident_id != plan.incident_id:
            raise InvestigationPlanMismatchError("Plan and state incident IDs differ")
        evidence_ids = {item.evidence_id for item in incident_state.evidence}
        if any(
            step.evidence_id is not None and step.evidence_id not in evidence_ids
            for step in plan.steps
        ):
            raise InvestigationPlanMismatchError(
                "Plan references evidence absent from incident state"
            )

    def prepare_step(
        self, *, incident_state: IncidentState, plan: InvestigationPlan, step_id: UUID
    ) -> ActionProposal:
        self._check_incident(incident_state, plan)
        step = plan.get_step(step_id)
        if step.status not in (InvestigationStepStatus.PENDING, InvestigationStepStatus.BLOCKED):
            raise InvestigationStepStateError("Only pending or blocked steps can be prepared")
        return ActionProposal(
            action_id=step.action_id,
            incident_id=plan.incident_id,
            tool_name=step.tool_name,
            tool_input=step.tool_input,
            created_at=plan.created_at,
        )

    async def execute_step(
        self,
        *,
        incident_state: IncidentState,
        plan: InvestigationPlan,
        step_id: UUID,
        approval_id: UUID | None = None,
    ) -> InvestigationResult:
        action = self.prepare_step(incident_state=incident_state, plan=plan, step_id=step_id)
        running = plan.transition_step(step_id, InvestigationStepStatus.RUNNING)
        try:
            tool_result = await self._executor.execute(action, approval_id=approval_id)
        except (ExecutionError, ApprovalError) as error:
            return self._failure(
                incident_state, running, step_id, InvestigationStepStatus.BLOCKED, error
            )
        except ToolError as error:
            return self._failure(
                incident_state, running, step_id, InvestigationStepStatus.FAILED, error
            )
        try:
            evidence = evidence_from_result(
                tool_result,
                incident_id=plan.incident_id,
                expected_tool_name=action.tool_name,
                observed_at=utc_now(),
            )
        except EvidenceConversionError as error:
            return self._failure(
                incident_state, running, step_id, InvestigationStepStatus.FAILED, error
            )
        updated_state = incident_state.add_evidence(evidence)
        completed = running.transition_step(
            step_id, InvestigationStepStatus.COMPLETED, evidence_id=evidence.evidence_id
        )
        return InvestigationResult(incident_state=updated_state, plan=completed)

    def _failure(
        self,
        state: IncidentState,
        plan: InvestigationPlan,
        step_id: UUID,
        status: InvestigationStepStatus,
        error: Exception,
    ) -> InvestigationResult:
        failure = StepFailure(
            error_type=type(error).__name__, reason=str(error) or type(error).__name__
        )
        return InvestigationResult(
            incident_state=state, plan=plan.transition_step(step_id, status, failure=failure)
        )

    async def execute_plan(
        self,
        *,
        incident_state: IncidentState,
        plan: InvestigationPlan,
        approval_ids: Mapping[UUID, UUID] | None = None,
    ) -> InvestigationResult:
        """At most one attempt per pending step; stop at the first block or failure."""
        self._check_incident(incident_state, plan)
        result = InvestigationResult(incident_state=incident_state, plan=plan)
        for step in plan.steps:
            if step.status == InvestigationStepStatus.COMPLETED:
                continue
            if step.status in (InvestigationStepStatus.BLOCKED, InvestigationStepStatus.FAILED):
                break
            result = await self.execute_step(
                incident_state=result.incident_state,
                plan=result.plan,
                step_id=step.step_id,
                approval_id=approval_ids.get(step.step_id) if approval_ids else None,
            )
            if result.plan.get_step(step.step_id).status != InvestigationStepStatus.COMPLETED:
                break
        return result
