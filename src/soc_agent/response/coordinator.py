"""Bounded sequential response via the governed executor only."""

from collections.abc import Mapping
from uuid import UUID

from soc_agent.approval.errors import ApprovalError
from soc_agent.execution import ActionProposal, ExecutionError, GovernedExecutor
from soc_agent.response.errors import (
    ResponsePlanMismatchError,
    ResponseStepStateError,
)
from soc_agent.response.models import (
    ResponsePlan,
    ResponseResult,
    ResponseStepStatus,
    StepFailure,
)
from soc_agent.state import IncidentState
from soc_agent.tools import ToolError


class ResponseCoordinator:
    """Only delegates execution; COMPLETED means tool success, not verified mitigation.

    Explicit execute_step may re-evaluate a BLOCKED step after human action;
    execute_plan stops on an existing block/failure until the caller resolves it.
    Cancellation propagates; durable recovery is not implemented.
    """

    def __init__(self, *, executor: GovernedExecutor) -> None:
        self._executor = executor

    def _check_incident(self, incident_state: IncidentState, plan: ResponsePlan) -> None:
        if incident_state.incident_id != plan.incident_id:
            raise ResponsePlanMismatchError("Plan and state incident IDs differ")

    def prepare_step(
        self, *, incident_state: IncidentState, plan: ResponsePlan, step_id: UUID
    ) -> ActionProposal:
        self._check_incident(incident_state, plan)
        step = plan.get_step(step_id)
        if step.status not in (ResponseStepStatus.PENDING, ResponseStepStatus.BLOCKED):
            raise ResponseStepStateError("Only pending or blocked steps can be prepared")
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
        plan: ResponsePlan,
        step_id: UUID,
        approval_id: UUID | None = None,
    ) -> ResponseResult:
        action = self.prepare_step(incident_state=incident_state, plan=plan, step_id=step_id)
        running = plan.transition_step(step_id, ResponseStepStatus.EXECUTING)
        try:
            await self._executor.execute(action, approval_id=approval_id)
        except (ExecutionError, ApprovalError) as error:
            return self._failure(
                incident_state, running, step_id, ResponseStepStatus.BLOCKED, error
            )
        except ToolError as error:
            return self._failure(incident_state, running, step_id, ResponseStepStatus.FAILED, error)
        completed = running.transition_step(step_id, ResponseStepStatus.COMPLETED)
        return ResponseResult(incident_state=incident_state, plan=completed)

    def _failure(
        self,
        state: IncidentState,
        plan: ResponsePlan,
        step_id: UUID,
        status: ResponseStepStatus,
        error: Exception,
    ) -> ResponseResult:
        failure = StepFailure(
            error_type=type(error).__name__, reason=str(error) or type(error).__name__
        )
        return ResponseResult(
            incident_state=state, plan=plan.transition_step(step_id, status, failure=failure)
        )

    async def execute_plan(
        self,
        *,
        incident_state: IncidentState,
        plan: ResponsePlan,
        approval_ids: Mapping[UUID, UUID] | None = None,
    ) -> ResponseResult:
        """At most one attempt per pending step; stop at the first block or failure."""
        self._check_incident(incident_state, plan)
        result = ResponseResult(incident_state=incident_state, plan=plan)
        for step in plan.steps:
            if step.status == ResponseStepStatus.COMPLETED:
                continue
            if step.status in (ResponseStepStatus.BLOCKED, ResponseStepStatus.FAILED):
                break
            result = await self.execute_step(
                incident_state=result.incident_state,
                plan=result.plan,
                step_id=step.step_id,
                approval_id=approval_ids.get(step.step_id) if approval_ids else None,
            )
            if result.plan.get_step(step.step_id).status != ResponseStepStatus.COMPLETED:
                break
        return result
