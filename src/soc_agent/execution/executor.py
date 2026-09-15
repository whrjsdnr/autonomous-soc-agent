"""Governance before registered, validated execution; no reasoning or retries."""

from uuid import UUID

from pydantic import BaseModel

from soc_agent.approval import ApprovalManager, ApprovalRequest, ApprovalStatus
from soc_agent.execution.binding import validate_binding
from soc_agent.execution.errors import (
    ActionAlreadyAttemptedError,
    ApprovalBindingError,
    ApprovalRejectedError,
    ApprovalRequiredError,
    ExecutionDeniedError,
)
from soc_agent.execution.models import ActionProposal
from soc_agent.policy import PolicyDecision, PolicyEngine
from soc_agent.tools import ToolRegistry, ToolResult


class GovernedExecutor:
    """Trusted composition root injects a registry, policy, and approval manager.

    Attempts are reserved before awaiting the tool, including failed/cancelled
    attempts. This prevents concurrent/repeated submissions within this executor
    and event loop. It is not durable or cross-process replay protection. Keep a
    single executor per runtime; creating a new executor resets attempt history.
    Do not expose the injected registry or human approval API to an LLM.
    """

    def __init__(
        self, *, registry: ToolRegistry, policy: PolicyEngine, approvals: ApprovalManager
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._approvals = approvals
        self._attempted: set[UUID] = set()

    def request_approval(self, action: ActionProposal, *, reason: str) -> ApprovalRequest:
        """Explicit request creation; never approves or executes anything."""
        action = ActionProposal.model_validate(action.model_dump(warnings=False))
        tool = self._registry.get(action.tool_name)
        result = self._policy.evaluate(tool.metadata)
        if result.decision != PolicyDecision.REQUIRE_APPROVAL:
            raise ExecutionDeniedError("Approval requests require a REQUIRE_APPROVAL policy result")
        return self._approvals.create(
            incident_id=action.incident_id,
            metadata=tool.metadata,
            reason=reason,
            action_id=action.action_id,
            action_input_json=action.tool_input,
        )

    async def execute(
        self,
        action: ActionProposal,
        *,
        approval_id: UUID | None = None,
        require_read_only: bool = False,
    ) -> ToolResult[BaseModel]:
        """Re-evaluate current policy; explicit approval ID avoids magic lookup."""
        action = ActionProposal.model_validate(action.model_dump(warnings=False))
        tool = self._registry.get(action.tool_name)
        if require_read_only and not tool.metadata.is_read_only_capability:
            raise ExecutionDeniedError("Caller requires an observation-only tool capability")
        result = self._policy.evaluate(tool.metadata)
        if result.decision == PolicyDecision.DENY:
            raise ExecutionDeniedError(result.reason)
        if result.decision == PolicyDecision.REQUIRE_APPROVAL:
            if approval_id is None:
                raise ApprovalRequiredError("Exact action approval is required")
            approval = self._approvals.get(approval_id)
            approval = ApprovalRequest.model_validate(approval.model_dump(warnings=False))
            validate_binding(action, approval, tool.metadata)
            if approval.status == ApprovalStatus.PENDING:
                raise ApprovalRequiredError("Action approval is pending")
            if approval.status == ApprovalStatus.REJECTED:
                raise ApprovalRejectedError("Action approval was rejected")
            if approval.status != ApprovalStatus.APPROVED:
                raise ApprovalBindingError("Unsupported approval status")
        elif result.decision != PolicyDecision.ALLOW:
            raise ExecutionDeniedError("Unsupported policy decision")
        if action.action_id in self._attempted:
            raise ActionAlreadyAttemptedError("Action has already been attempted by this executor")
        self._attempted.add(action.action_id)
        return await tool.execute(action.input_payload())
