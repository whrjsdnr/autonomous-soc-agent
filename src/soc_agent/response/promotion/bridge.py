"""Explicit execution entry point with final validation and existing approval/executor reuse."""

from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel

from soc_agent.approval import ApprovalManager, ApprovalRequest, ApprovalStatus
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.binding import validate_binding
from soc_agent.execution.errors import ApprovalBindingError, ApprovalRequiredError
from soc_agent.policy import PolicyDecision
from soc_agent.response.promotion.models import ExecutionProvenance, PromotedAction
from soc_agent.response.promotion.service import PromotionService, confirm
from soc_agent.review.authority import DenyHumanAuthority, HumanAction, HumanAuthority
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.review.validation import checked
from soc_agent.tools import ToolResult


class ToolApprovalIntent(Frozen):
    promoted_id: Hash
    approval: ApprovalRequest


class ExecutionBridge:
    def __init__(
        self,
        *,
        promotions: PromotionService,
        approvals: ApprovalManager,
        authority: HumanAuthority | None = None,
    ) -> None:
        self._promotions, self._approvals = promotions, approvals
        self._authority = authority if authority is not None else DenyHumanAuthority()
        current = promotions.validation
        self._executor = GovernedExecutor(
            registry=current.registry, policy=current.policy, approvals=approvals
        )
        self._links: dict[UUID, str] = {}
        self._confirmed: dict[UUID, ApprovalRequest] = {}
        self._events: list[ExecutionProvenance] = []

    def executable_action(self, promoted: PromotedAction) -> ActionProposal:
        promoted = self._promotions.validate_promoted(promoted)
        target = promoted.content.request.target
        return ActionProposal(
            action_id=uuid5(NAMESPACE_URL, "soc-agent:response-promotion:" + promoted.promoted_id),
            incident_id=target.incident_id,
            tool_name=target.proposal.details.intent.candidate_tool,
            tool_input=target.proposal.details.intent.proposed_input,
            created_at=promoted.created_at,
        )

    def request_approval(self, promoted: PromotedAction, *, reason: str) -> ApprovalRequest:
        """Explicitly create PENDING only; never called by planning or promotion."""
        action = self.executable_action(promoted)
        request = self._executor.request_approval(action, reason=reason)
        self._links[request.approval_id] = promoted.promoted_id
        return request

    def _approval(self, promoted: PromotedAction, approval_id: UUID) -> ApprovalRequest:
        if type(approval_id) is not UUID or self._links.get(approval_id) != promoted.promoted_id:
            raise ApprovalBindingError("Approval is not linked to this exact promotion")
        approval = checked(ApprovalRequest, self._approvals.get(approval_id))
        action = self.executable_action(promoted)
        metadata = self._promotions.validation.registry.get(action.tool_name).metadata
        validate_binding(action, approval, metadata)
        return approval

    def approval_intent(self, promoted: PromotedAction, approval_id: UUID) -> ToolApprovalIntent:
        approval = self._approval(promoted, approval_id)
        if approval.status != ApprovalStatus.PENDING:
            raise ApprovalBindingError("Only pending Tool Approval can receive human confirmation")
        return ToolApprovalIntent(promoted_id=promoted.promoted_id, approval=approval)

    def approve_tool(
        self, promoted: PromotedAction, approval_id: UUID, *, credential: str
    ) -> ApprovalRequest:
        """Independent explicit human Tool Approval, not a promotion side effect."""
        intent = self.approval_intent(promoted, approval_id)
        actor = confirm(
            self._authority, credential, HumanAction.APPROVE_PROMOTED_TOOL, content_digest(intent)
        )
        if self.approval_intent(promoted, approval_id) != intent:
            raise ApprovalBindingError("Approval changed during human confirmation")
        result = self._approvals.approve(approval_id, actor=actor)
        self._confirmed[approval_id] = result
        return result

    def _event(
        self,
        promoted: PromotedAction,
        action: ActionProposal,
        approval_id: UUID | None,
        outcome: str,
        error: BaseException | None = None,
    ) -> None:
        request = promoted.content.request
        self._events.append(
            ExecutionProvenance(
                promoted_id=promoted.promoted_id,
                incident_id=request.target.incident_id,
                response_plan_id=request.target.response_plan_id,
                proposal_id=request.target.proposal.proposal_id,
                response_review_id=request.review.review_id,
                promotion_request_id=request.request_id,
                action_id=action.action_id,
                approval_id=approval_id,
                snapshot=promoted.content.current_snapshot,
                outcome=outcome,
                error_type=type(error).__name__ if error else None,
            )
        )

    async def execute(
        self, promoted: PromotedAction, *, approval_id: UUID | None = None
    ) -> ToolResult[BaseModel]:
        """Explicit call only. Point-in-time checks, no distributed state/tool transaction."""
        # Revalidate provenance before deriving an executable ID or accepting any approval.
        promoted = checked(PromotedAction, promoted)
        target = promoted.content.request.target
        action = ActionProposal(
            action_id=uuid5(NAMESPACE_URL, "soc-agent:response-promotion:" + promoted.promoted_id),
            incident_id=target.incident_id,
            tool_name=target.proposal.details.intent.candidate_tool,
            tool_input=target.proposal.details.intent.proposed_input,
            created_at=promoted.created_at,
        )
        safe_id = approval_id if type(approval_id) is UUID else None
        try:
            self.executable_action(promoted)
            if approval_id is not None:
                approval = self._approval(promoted, approval_id)
                if self._confirmed.get(approval_id) != approval:
                    raise ApprovalRequiredError("Independent trusted Tool Approval is absent")
            elif promoted.content.current_policy.decision == PolicyDecision.REQUIRE_APPROVAL:
                raise ApprovalRequiredError("Promotion is not a Tool Approval")
        except Exception as error:
            self._event(promoted, action, safe_id, "rejected", error)
            raise
        self._event(promoted, action, safe_id, "started")
        try:
            result = await self._executor.execute(action, approval_id=approval_id)
        except BaseException as error:
            self._event(
                promoted,
                action,
                safe_id,
                "failed" if isinstance(error, Exception) else "outcome_unknown",
                error,
            )
            raise
        self._event(promoted, action, safe_id, "succeeded")
        return result

    def audit_events(self) -> tuple[ExecutionProvenance, ...]:
        return tuple(self._events)
