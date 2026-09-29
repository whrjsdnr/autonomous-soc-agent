import pytest
from tests.unit.advisory.conftest import create
from tests.unit.advisory.conftest import planning as planning
from tests.unit.persistence.conftest import case as case

from soc_agent.approval import ApprovalManager
from soc_agent.policy import PolicyEngine, PolicyResult
from soc_agent.response.promotion import (
    BlockerResponse,
    ExecutionBridge,
    PromotionService,
    ReviewDisposition,
)
from soc_agent.review.authority import HumanAction
from soc_agent.review.identity import content_digest


class CurrentPolicy(PolicyEngine):
    override = None

    def evaluate(self, metadata):
        return (
            PolicyResult(decision=self.override, reason="Test current policy")
            if self.override
            else super().evaluate(metadata)
        )


@pytest.fixture
def workflow(planning):
    state, _, _, store, _, registry, _, candidate, authority = planning
    policy = CurrentPolicy()
    service = PromotionService(store=store, registry=registry, policy=policy, authority=authority)
    approvals = ApprovalManager()
    bridge = ExecutionBridge(promotions=service, approvals=approvals, authority=authority)
    plan = create(
        planning,
        (
            candidate,
            candidate.model_copy(update={"candidate_tool": "test_response"}),
            candidate.model_copy(update={"candidate_tool": "test_destructive"}),
        ),
    )
    return planning, plan, policy, service, approvals, bridge, authority


def reviewed(workflow, tool="inspect_logs", disposition=ReviewDisposition.READY_FOR_PROMOTION):
    _, plan, _, service, _, _, authority = workflow
    proposal = next(p for p in plan.proposed_actions if p.details.intent.candidate_tool == tool)
    intent = service.request_review(
        plan,
        proposal.proposal_id,
        reviewer_id="reviewer-alice",
        disposition=disposition,
        reason="Explicit human consideration for promotion only",
        blocker_responses=tuple(
            BlockerResponse(
                blocking_reason=r,
                resolution="addressed_for_promotion",
                response="Human considered this condition; separate Tool Approval is required.",
            )
            for r in proposal.details.blocking_reasons
        ),
    )
    token = authority.confirm(
        subject="reviewer-alice",
        action=HumanAction.REVIEW_RESPONSE_ACTION,
        digest=content_digest(intent),
    )
    return service.record_review(intent, credential=token)


def promoted(workflow, tool="inspect_logs"):
    return workflow[3].promote(workflow[3].request_promotion(reviewed(workflow, tool)))


def approve(workflow, value):
    bridge, authority = workflow[5], workflow[6]
    request = bridge.request_approval(value, reason="Separate explicit Tool Approval")
    intent = bridge.approval_intent(value, request.approval_id)
    token = authority.confirm(
        subject="approver-bob",
        action=HumanAction.APPROVE_PROMOTED_TOOL,
        digest=content_digest(intent),
    )
    return bridge.approve_tool(value, request.approval_id, credential=token)
