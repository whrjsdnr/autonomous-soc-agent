import pytest

from soc_agent.approval import ApprovalManager
from soc_agent.execution.durable import (
    DurableExecutor,
    ExecutionStore,
    Lifecycle,
    ReconciledOutcome,
    ReconciliationRequest,
    migrate,
)
from soc_agent.execution.errors import ApprovalRequiredError
from soc_agent.policy import PolicyEngine
from soc_agent.response.promotion import (
    BlockerResponse,
    ExecutionBridge,
    PromotionService,
    ReviewDisposition,
)
from soc_agent.response.promotion.errors import PromotionPolicyDenied
from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewIntent, ReviewOutcome
from soc_agent.review.persistence import PersistentHumanReviewService


def credential(boundary, state, decision, action, intent, roles):
    ctx = HumanActionContext(
        incident_id=state.incident_id,
        decision_id=decision.decision_id,
        action=action,
        binding_digest=content_digest(intent),
    )
    return boundary.issue(ctx, roles)


@pytest.fixture
def flow(planning, boundary):
    state, decision, _, store, _, registry, planner, candidate, _ = planning
    incidents = PersistentHumanReviewService(store=store, authority=boundary.authority)
    request = incidents.request_review(state, decision)
    intent = ReviewIntent(
        review_request_id=request.review_request_id,
        target=request.target,
        reviewer_id="reviewer-alice",
        outcome=ReviewOutcome.ACKNOWLEDGED,
        reason="Authenticated analyst review, not Tool Approval",
    )
    token = credential(
        boundary, state, decision, HumanAction.RECORD_REVIEW, intent, (HumanRole.ANALYST,)
    )
    review = incidents.record_review(
        request,
        reviewer_id=intent.reviewer_id,
        outcome=intent.outcome,
        reason=intent.reason,
        credential=token,
    )
    plan = planner.create_plan(
        incident_state=state,
        decision=decision,
        review=review,
        objective="Human governed options",
        candidates=(
            candidate,
            candidate.model_copy(update={"candidate_tool": "test_response"}),
            candidate.model_copy(update={"candidate_tool": "test_destructive"}),
        ),
    )
    promotions = PromotionService(
        store=store, registry=registry, policy=PolicyEngine(), authority=boundary.authority
    )
    bridge = ExecutionBridge(
        promotions=promotions, approvals=ApprovalManager(), authority=boundary.authority
    )
    return state, decision, store, registry, promotions, bridge, plan, boundary


def promote(flow, tool="test_response", roles=(HumanRole.RESPONDER,)):
    state, decision, _, _, service, _, plan, boundary = flow
    proposal = next(p for p in plan.proposed_actions if p.details.intent.candidate_tool == tool)
    intent = service.request_review(
        plan,
        proposal.proposal_id,
        reviewer_id="reviewer-alice",
        disposition=ReviewDisposition.READY_FOR_PROMOTION,
        reason="Response-specific review",
        blocker_responses=tuple(
            BlockerResponse(
                blocking_reason=r,
                resolution="addressed_for_promotion",
                response="Explicit human consideration",
            )
            for r in proposal.details.blocking_reasons
        ),
    )
    token = credential(boundary, state, decision, HumanAction.REVIEW_RESPONSE_ACTION, intent, roles)
    review = service.record_review(intent, credential=token)
    return service.promote(service.request_promotion(review))


def approve(flow, promoted, roles=(HumanRole.APPROVER,)):
    state, decision, _, _, _, bridge, _, boundary = flow
    request = bridge.request_approval(promoted, reason="Independent exact human Tool Approval")
    intent = bridge.approval_intent(promoted, request.approval_id)
    token = credential(boundary, state, decision, HumanAction.APPROVE_PROMOTED_TOOL, intent, roles)
    return bridge.approve_tool(promoted, request.approval_id, credential=token)


@pytest.mark.asyncio
async def test_identity_through_review_approval_and_durable_execution(flow):
    _, _, governance, registry, _, bridge, _, boundary = flow
    value = promote(flow)
    # Neither Incident Review nor Response Review grants a Tool Approval.
    with pytest.raises(ApprovalRequiredError):
        await bridge.execute(value)
    approval = approve(flow, value)
    migrate(governance.database)
    store = ExecutionStore(governance)
    record = store.create(bridge, value, approval_id=approval.approval_id)
    result = await DurableExecutor(store=store, registry=registry, policy=PolicyEngine()).execute(
        record.intent.execution_intent_id, claimant="test-worker"
    )
    assert result.tool_name == "test_response"
    assert store.load(record.intent.execution_intent_id).state == Lifecycle.SUCCEEDED
    receipts = boundary.authority.verification_records()
    assert [r.context.action for r in receipts] == [
        HumanAction.RECORD_REVIEW,
        HumanAction.REVIEW_RESPONSE_ACTION,
        HumanAction.APPROVE_PROMOTED_TOOL,
    ]
    assert all(
        r.subject_id == "reviewer-alice" and r.provider_id == "test-identity" for r in receipts
    )


def test_response_review_requires_responder(flow):
    with pytest.raises(HumanAuthorizationDenied):
        promote(flow, roles=(HumanRole.ANALYST,))
    assert flow[4].reviews() == ()


def test_tool_approval_requires_approver(flow):
    value = promote(flow)
    with pytest.raises(HumanAuthorizationDenied):
        approve(flow, value, roles=(HumanRole.RESPONDER,))


def test_admin_does_not_override_policy(flow):
    with pytest.raises(PromotionPolicyDenied):
        promote(flow, tool="test_destructive", roles=(HumanRole.ADMIN,))
    assert flow[4].promoted_actions() == ()


@pytest.mark.asyncio
async def test_admin_still_needs_exact_tool_approval(flow):
    value = promote(flow, roles=(HumanRole.ADMIN,))
    with pytest.raises(ApprovalRequiredError):
        await flow[5].execute(value)


@pytest.mark.parametrize(
    "roles,allowed", [((HumanRole.ANALYST,), False), ((HumanRole.APPROVER,), True)]
)
def test_reconciliation_specific_permission(flow, roles, allowed):
    state, decision, governance, _, _, bridge, _, boundary = flow
    value = promote(flow)
    approval = approve(flow, value)
    migrate(governance.database)
    store = ExecutionStore(governance)
    record = store.create(bridge, value, approval_id=approval.approval_id)
    claimed = store.claim(record.intent.execution_intent_id, claimant="stopped-worker")
    running = store.transition(claimed, Lifecycle.EXECUTING)
    uncertain = store.transition(running, Lifecycle.UNCERTAIN, reason="Remote outcome unknown")
    request = ReconciliationRequest(
        execution_intent_id=record.intent.execution_intent_id,
        incident_id=state.incident_id,
        expected_revision=uncertain.revision,
        outcome=ReconciledOutcome.CONFIRMED_SUCCEEDED,
        reason="Operator verified outcome",
        references=("test-verification:1",),
    )
    token = credential(boundary, state, decision, HumanAction.RECONCILE_EXECUTION, request, roles)
    if allowed:
        result = store.reconcile(request, credential=token, authority=boundary.authority)
        assert result.state == Lifecycle.SUCCEEDED
        assert (
            store.events(record.intent.execution_intent_id)[-1].reconciliation.actor
            == "reviewer-alice"
        )
        assert boundary.authority.verification_records()[
            -1
        ].context.binding_digest == content_digest(request)
    else:
        with pytest.raises(HumanAuthorizationDenied):
            store.reconcile(request, credential=token, authority=boundary.authority)
        assert store.load(record.intent.execution_intent_id) == uncertain
