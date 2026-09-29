import asyncio
from uuid import uuid4

import pytest
from tests.unit.promotion.conftest import approve, promoted

from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.execution.errors import (
    ActionAlreadyAttemptedError,
    ApprovalBindingError,
    ApprovalRequiredError,
)
from soc_agent.policy import PolicyDecision
from soc_agent.response.promotion import ExecutionBridge
from soc_agent.response.promotion.errors import (
    InvalidPromotionArtifact,
    PromotionPolicyChanged,
    PromotionPolicyDenied,
)
from soc_agent.review import HumanAuthorizationDenied
from soc_agent.review.errors import StaleSnapshotError
from soc_agent.state import Evidence
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolRegistry


@pytest.mark.asyncio
async def test_read_only_execution_and_provenance(workflow):
    value = promoted(workflow)
    before = workflow[0][3].load(value.content.request.target.incident_id)
    result = await workflow[5].execute(value)
    assert result.output.result == "ok"
    assert workflow[4].list() == ()
    assert workflow[0][3].load(before.state.incident_id) == before
    events = workflow[5].audit_events()
    assert [e.outcome for e in events] == ["started", "succeeded"]
    assert events[-1].proposal_id == value.content.request.target.proposal.proposal_id
    assert events[-1].response_review_id == value.content.request.review.review_id


@pytest.mark.asyncio
async def test_write_needs_separate_confirmation_and_replay_rejected(workflow):
    value = promoted(workflow, "test_response")
    bridge = workflow[5]
    with pytest.raises(ApprovalRequiredError):
        await bridge.execute(value)
    approval = approve(workflow, value)
    action = bridge.executable_action(value)
    assert approval.action_id == action.action_id
    assert approval.action_input_json == action.tool_input
    assert approval.permission == value.content.request.target.proposal.details.metadata.permission
    assert (await bridge.execute(value, approval_id=approval.approval_id)).output.result == "ok"
    with pytest.raises(ActionAlreadyAttemptedError):
        await bridge.execute(value, approval_id=approval.approval_id)
    assert sum(e.outcome == "succeeded" for e in bridge.audit_events()) == 1


@pytest.mark.asyncio
async def test_pending_and_plain_actor_do_not_authorize_bridge(workflow):
    value = promoted(workflow, "test_response")
    bridge = workflow[5]
    request = bridge.request_approval(value, reason="Independent approval needed")
    for direct_approval in (False, True):
        if direct_approval:
            workflow[4].approve(request.approval_id, actor="arbitrary name")
        with pytest.raises(ApprovalRequiredError):
            await bridge.execute(value, approval_id=request.approval_id)


def test_default_tool_confirmation_denied(workflow):
    value = promoted(workflow, "test_response")
    bridge = ExecutionBridge(promotions=workflow[3], approvals=ApprovalManager())
    approval = bridge.request_approval(value, reason="Needs authenticated human")
    with pytest.raises(HumanAuthorizationDenied):
        bridge.approve_tool(value, approval.approval_id, credential="approver-bob")


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["state", "policy_deny", "policy_requires", "tool"])
async def test_execution_time_change_rejected(workflow, change):
    value = promoted(workflow)
    if change == "state":
        state = workflow[0][0]
        workflow[0][3].append_evidence(
            value.content.current_snapshot,
            Evidence(
                incident_id=state.incident_id,
                source="later",
                summary="Changed",
                raw_data="{}",
                observed_at=utc_now(),
            ),
        )
        error = StaleSnapshotError
    elif change == "tool":
        from soc_agent.response.promotion.errors import PromotionToolMissing

        del workflow[0][5]._tools["inspect_logs"]
        error = PromotionToolMissing
    else:
        workflow[2].override = (
            PolicyDecision.DENY if change == "policy_deny" else PolicyDecision.REQUIRE_APPROVAL
        )
        error = PromotionPolicyDenied if change == "policy_deny" else PromotionPolicyChanged
    with pytest.raises(error):
        await workflow[5].execute(value)
    assert workflow[5].audit_events()[-1].outcome == "rejected"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("tool_name", "inspect_logs"),
        ("action_input_json", '{"target":"other"}'),
        ("incident_id", uuid4()),
        ("action_id", uuid4()),
        ("permission", "network_read"),
    ],
)
async def test_approval_substitution(workflow, field, value):
    action = promoted(workflow, "test_response")
    approval = approve(workflow, action)
    # Attack against the manager's private ledger; public approval models stay frozen.
    workflow[4]._requests[approval.approval_id] = approval.model_copy(update={field: value})
    with pytest.raises(ApprovalBindingError):
        await workflow[5].execute(action, approval_id=approval.approval_id)


@pytest.mark.asyncio
async def test_other_proposal_approval_and_state_authorization_rejected(workflow):
    from tests.review_support import authorize

    from soc_agent.review import SeverityChange

    first = promoted(workflow, "test_response")
    approval = approve(workflow, first)
    second = promoted(workflow, "test_response")
    assert first.promoted_id != second.promoted_id
    with pytest.raises(ApprovalBindingError):
        await workflow[5].execute(second, approval_id=approval.approval_id)
    planning = workflow[0]
    request = planning[4].propose_change(
        planning[2], changes=(SeverityChange(before="info", after="high"),), reason="State only"
    )
    state_auth = authorize(planning[4], planning[8], request, planning[2])
    for wrong in (state_auth, state_auth.authorization_id):
        with pytest.raises(ApprovalBindingError):
            await workflow[5].execute(first, approval_id=wrong)


def test_promote_has_no_execution_or_approval_dependencies(workflow, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Promotion crossed execution/approval/registry boundary")

    for cls, method in (
        (GovernedExecutor, "execute"),
        (GovernedExecutor, "request_approval"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (Tool, "execute"),
        (ToolRegistry, "register"),
    ):
        monkeypatch.setattr(cls, method, forbidden)
    value = promoted(workflow, "test_response")
    assert value.content.current_policy.decision == PolicyDecision.REQUIRE_APPROVAL


@pytest.mark.asyncio
async def test_forged_promoted_object_rejected(workflow):
    value = promoted(workflow)
    with pytest.raises((InvalidPromotionArtifact, ValueError)):
        await workflow[5].execute(value.model_copy(update={"promoted_id": "0" * 64}))


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_execution_failure_never_retries_and_records_uncertainty(
    workflow, monkeypatch, cancel
):
    from soc_agent.tools.errors import ToolExecutionError

    value = promoted(workflow)
    calls = 0

    async def failed(self, payload):
        nonlocal calls
        calls += 1
        if cancel:
            raise asyncio.CancelledError()
        raise ToolExecutionError("Test adapter failure")

    monkeypatch.setattr(Tool, "execute", failed)
    with pytest.raises(asyncio.CancelledError if cancel else ToolExecutionError):
        await workflow[5].execute(value)
    assert workflow[5].audit_events()[-1].outcome == ("outcome_unknown" if cancel else "failed")
    with pytest.raises(ActionAlreadyAttemptedError):
        await workflow[5].execute(value)
    assert calls == 1
