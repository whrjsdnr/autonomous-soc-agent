"""Real API/runtime/governance with synthetic reports, scripted LLM and test-only identity.

No saved model is loaded here. Unconfigured inference is explicitly NOT_RUN.
"""

import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from soc_agent.api import SOCApplication
from soc_agent.demo.composition import compose_demo
from soc_agent.response.promotion.models import ResponseReviewIntent
from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewIntent
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.state import Evidence
from soc_agent.state.evidence import utc_now
from tests.integration.api.conftest import TestAccess as DemoAccess
from tests.integration.api.conftest import call
from tests.integration.demo.conftest import ingest, step


def confirm(d, action, value, role):
    saved = d.service.checkpoint(d.incident_id)
    return d.b.issue(
        HumanActionContext(
            incident_id=d.incident_id,
            action=action,
            binding_digest=content_digest(value),
            decision_id=saved.artifacts.decision.decision_id,
        ),
        (role,),
    )


async def prepared(d, event):
    await ingest(d, event)
    assert (await call(d.app, "POST", d.base + "/workflow/start", token=d.token))[0] == 200
    for _ in range(12):
        status, result = await step(d)
        assert status == 200, result
        if result["current_step"] == "decide":
            break
    else:
        pytest.fail("Decision not reached")
    assert d.service.checkpoint(d.incident_id).artifacts.decision
    return result


async def reviewed(d):
    status, request = await call(d.app, "POST", d.base + "/review-requests", token=d.token)
    assert status == 200
    intent = ReviewIntent(
        review_request_id=request["review_request_id"],
        target=request["target"],
        reviewer_id="reviewer-alice",
        outcome="state_change_may_be_proposed",
        reason="Demo source reviewed; not confirmed compromise",
    )
    token = confirm(d, HumanAction.RECORD_REVIEW, intent, HumanRole.ANALYST)
    status, result = await call(
        d.app,
        "POST",
        d.base + "/reviews",
        {
            "request_id": str(intent.review_request_id),
            "reviewer_id": intent.reviewer_id,
            "outcome": intent.outcome,
            "reason": intent.reason,
        },
        token,
    )
    assert status == 200, result
    assert (await step(d, review_id=result["review_id"]))[0] == 200


async def promoted(d, write=True):
    await reviewed(d)
    state = d.store.load(d.incident_id).state
    name = "disable_demo_account" if write else "read_demo_authentication"
    value = {"account_id": "demo-alice"} if write else {"incident_id": str(d.incident_id)}
    status, result = await step(
        d,
        candidates=[
            {
                "candidate_tool": name,
                "proposed_input": value,
                "purpose": "Demonstrate governed simulation",
                "rationale": "Human review required",
                "evidence_ids": [str(state.evidence[0].evidence_id)],
            }
        ],
    )
    assert status == 200, result
    plan = d.service.checkpoint(d.incident_id).artifacts.response_plan
    assert plan is not None, result
    proposal = plan.proposed_actions[0]
    status, raw = await call(
        d.app,
        "POST",
        d.base + "/response-review-requests",
        {
            "proposal_id": proposal.proposal_id,
            "reviewer_id": "reviewer-alice",
            "disposition": "ready_for_promotion",
            "reason": "Only simulation considered",
            "blocker_responses": [
                {
                    "blocking_reason": reason,
                    "resolution": "addressed_for_promotion",
                    "response": "Reviewed limitation; independent approval still needed",
                }
                for reason in proposal.details.blocking_reasons
            ],
        },
        d.token,
    )
    assert status == 200, raw
    intent = ResponseReviewIntent.model_validate(raw)
    token = confirm(d, HumanAction.REVIEW_RESPONSE_ACTION, intent, HumanRole.RESPONDER)
    status, response = await call(
        d.app, "POST", d.base + "/response-reviews", {"intent_id": str(intent.intent_id)}, token
    )
    assert status == 200, response
    status, promoted_value = await call(
        d.app, "POST", d.base + "/promotions", {"review_id": response["review_id"]}, d.token
    )
    assert status == 200, promoted_value
    return promoted_value["promoted_id"]


async def approved(d, identity):
    body = {"promoted_id": identity, "reason": "Separate explicit Tool Approval"}
    status, pending = await call(d.app, "POST", d.base + "/approval-requests", body, d.token)
    assert status == 200
    intent = d.service.bridge.approval_intent(
        d.service.promoted(d.incident_id, identity), UUID(pending["approval_id"])
    )
    token = confirm(d, HumanAction.APPROVE_PROMOTED_TOOL, intent, HumanRole.APPROVER)
    body = {"promoted_id": identity, "approval_id": pending["approval_id"]}
    status, result = await call(d.app, "POST", d.base + "/approvals", body, token)
    assert status == 200, result
    assert (await call(d.app, "POST", d.base + "/approvals", body, token))[0] != 200
    return pending["approval_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("write", [False, True])
async def test_demo_lifecycle_pause_exact_approval_trace(demo, event, write):
    if not write:
        event = json.loads(
            (Path(__file__).parents[3] / "examples/authentication/benign.json").read_text()
        )
    await prepared(demo, event)
    checkpoint = demo.service.checkpoint(demo.incident_id)
    assessment = checkpoint.artifacts.assessment
    assert assessment.model_derived_context.coverage[0].status == "not_run"
    state = demo.store.load(demo.incident_id).state
    assert state.severity == "info"
    assert all(e.tool_name == "read_demo_authentication" for e in state.evidence)
    assert not state.observations  # Fusion-aware scripted assessment never invents observations.
    identity = await promoted(demo, write)
    status, result = await step(demo, promoted_id=identity, execute=True)
    assert status == 200
    if write:
        assert result["waiting_for_human"] and result["next_step"] == "govern"
        assert demo.service.checkpoint(demo.incident_id).artifacts.execution_intent_id is None
        approval = await approved(demo, identity)
        assert (await step(demo, promoted_id=identity, approval_id=approval))[1][
            "next_step"
        ] == "act"
    assert (await step(demo, execute=True))[1]["next_step"] == "evaluate"
    assert (await step(demo))[1]["terminal"]
    checkpoint = demo.service.checkpoint(demo.incident_id)
    execution = demo.service.execution.load(checkpoint.artifacts.execution_intent_id)
    assert execution.state == "succeeded" and execution.result_digest
    if write:
        assert execution.intent.binding.approval_id is not None
        assert execution.intent.binding.tool_name == "disable_demo_account"
    status, trace = await call(demo.app, "GET", demo.base + "/trace", token=demo.token)
    assert status == 200
    results = [e["content"]["result"] for e in trace["entries"]]
    assert {"observe", "plan", "route", "analyze", "decide", "govern", "act", "evaluate"} <= {
        r["current_step"] for r in results
    }
    if write:
        assert any(r["waiting_for_human"] for r in results)
    assert demo.store.load(demo.incident_id).state.status == "new"


@pytest.mark.asyncio
async def test_restart_waiting_preserves_analysis(demo, event):
    await prepared(demo, event)
    # Advance into the existing investigation loop guard, not an invented demo transition.
    for _ in range(4):
        result = (await step(demo))[1]
        if result["waiting_for_human"]:
            break
    assert result["waiting_for_human"]
    before = demo.service.checkpoint(demo.incident_id)
    trace = demo.service.trace(demo.incident_id)
    reopened = SQLiteGovernanceStore(demo.store.database.path)
    demo.service = compose_demo(reopened, authority=demo.authority)
    demo.app = SOCApplication(
        lambda: demo.service,
        provider=demo.b.provider,
        provider_id="test-identity",
        access=DemoAccess(),
    )
    assert demo.service.workflow(demo.incident_id).waiting_for_human
    identity = await promoted(demo)
    approval = await approved(demo, identity)
    assert (await step(demo, promoted_id=identity, approval_id=approval))[0] == 200
    assert (await step(demo, execute=True))[1]["next_step"] == "evaluate"
    assert (await step(demo))[1]["terminal"]
    assert (
        demo.service.checkpoint(demo.incident_id).artifacts.assessment
        == before.artifacts.assessment
    )
    assert demo.service.trace(demo.incident_id).entries[: len(trace.entries)] == trace.entries


@pytest.mark.asyncio
async def test_forged_stale_and_cross_incident_approval(demo, event):
    await prepared(demo, event)
    identity = await promoted(demo)
    forged = await step(demo, promoted_id=identity, approval_id=str(uuid4()), execute=True)
    assert forged[0] == 200 and forged[1]["failure"] == "validation_failure"
    assert demo.service.checkpoint(demo.incident_id).artifacts.execution_intent_id is None
    approval = await approved(demo, identity)
    foreign = await call(
        demo.app,
        "POST",
        f"/incidents/{uuid4()}/approvals",
        {"promoted_id": identity, "approval_id": approval},
        demo.token,
    )
    assert foreign[0] == 404
    current = demo.store.load(demo.incident_id)
    demo.store.append_evidence(
        current.anchor,
        Evidence(
            incident_id=demo.incident_id,
            source="test",
            summary="New report",
            raw_data="{}",
            observed_at=utc_now(),
        ),
    )
    assert (await step(demo, promoted_id=identity, approval_id=approval, execute=True))[0] == 409
    assert demo.service.checkpoint(demo.incident_id).artifacts.execution_intent_id is None


@pytest.mark.asyncio
async def test_uncertain_no_retry_after_restart(demo, event, monkeypatch):
    await prepared(demo, event)
    identity = await promoted(demo)
    approval = await approved(demo, identity)
    assert (await step(demo, promoted_id=identity, approval_id=approval))[0] == 200
    # Inject a crash after durable invocation boundary; never change the demo Tool's behavior.
    original = demo.service.execution.transition

    def interrupted(record, state, **kwargs):
        result = original(record, state, **kwargs)
        if str(state) == "executing":
            raise TimeoutError("Invocation outcome unavailable")
        return result

    monkeypatch.setattr(demo.service.execution, "transition", interrupted)
    status, outcome = await step(demo, execute=True)
    assert status == 200 and outcome["next_step"] == "recover"
    monkeypatch.undo()
    from datetime import timedelta

    from soc_agent.execution.durable import store as execution_storage

    future = utc_now() + timedelta(hours=1)
    monkeypatch.setattr(execution_storage, "utc_now", lambda: future)
    recovered = demo.service.execution.recover()
    assert len(recovered) == 1 and recovered[0].state == "uncertain"
    monkeypatch.undo()
    reopened = SQLiteGovernanceStore(demo.store.database.path)
    demo.service = compose_demo(reopened, authority=demo.authority)
    demo.app = SOCApplication(
        lambda: demo.service,
        provider=demo.b.provider,
        provider_id="test-identity",
        access=DemoAccess(),
    )
    for _ in range(2):
        assert (await step(demo, execute=True))[1]["next_step"] == "recover"
    execution = demo.service.execution.load(
        demo.service.checkpoint(demo.incident_id).artifacts.execution_intent_id
    )
    assert execution.state == "uncertain"
    assert execution.revision == recovered[0].revision


@pytest.mark.asyncio
@pytest.mark.parametrize("account", ["root", "demo-alice;id", "real-account"])
async def test_demo_tool_rejects_non_allowlisted_subject_via_executor(demo, account):
    from soc_agent.demo.tools import DemoIdentityInput
    from soc_agent.execution import ActionProposal, GovernedExecutor
    from soc_agent.execution.errors import ApprovalRequiredError
    from soc_agent.tools.errors import ToolInputValidationError

    with pytest.raises(ValueError):
        DemoIdentityInput(account_id=account)
    action = ActionProposal(
        incident_id=uuid4(), tool_name="disable_demo_account", tool_input={"account_id": account}
    )
    executor = GovernedExecutor(
        registry=demo.service.promotions.validation.registry,
        policy=demo.service.promotions.validation.policy,
        approvals=demo.service.bridge._approvals,
    )
    with pytest.raises((ToolInputValidationError, ApprovalRequiredError)):
        await executor.execute(action)


@pytest.mark.asyncio
async def test_api_rejects_identity_and_protected_payload(demo, event):
    assert (await call(demo.app, "POST", "/events", event, "admin"))[0] == 401
    assert (await call(demo.app, "POST", "/events", {**event, "approved": True}, demo.token))[
        0
    ] == 422
