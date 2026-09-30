import asyncio
from uuid import uuid4

import pytest

from soc_agent.api import SOCApplication
from soc_agent.api.startup import open_store
from soc_agent.response.promotion.models import ResponseReviewIntent
from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewIntent
from soc_agent.review.persistence.models import CommitOutcomeUnknown
from tests.integration.api.conftest import call, step


async def decision(a):
    for _ in range(4):
        status, _ = await step(a)
        assert status == 200
    assert a.c.llm.calls == 1


async def review(a, roles=(HumanRole.ANALYST,)):
    status, request = await call(a.app, "POST", a.base + "/review-requests", token=a.token)
    assert status == 200
    intent = ReviewIntent(
        review_request_id=request["review_request_id"],
        target=request["target"],
        reviewer_id="reviewer-alice",
        outcome="state_change_may_be_proposed",
        reason="Checked",
    )
    token = a.b.issue(
        HumanActionContext(
            incident_id=a.c.incident_id,
            action=HumanAction.RECORD_REVIEW,
            binding_digest=content_digest(intent),
            decision_id=intent.target.decision_id,
        ),
        roles,
    )
    body = {
        "request_id": request["review_request_id"],
        "reviewer_id": intent.reviewer_id,
        "outcome": intent.outcome,
        "reason": intent.reason,
    }
    status, result = await call(a.app, "POST", a.base + "/reviews", body, token)
    return status, result, body, token


async def promote(a, write=False):
    await decision(a)
    status, result, _, _ = await review(a)
    assert status == 200
    assert (await step(a, review_id=result["review_id"]))[0] == 200
    evidence = a.c.store.load(a.c.incident_id).state.evidence[0]
    tool = "test_response" if write else "inspect_logs"
    assert (
        await step(
            a,
            candidates=[
                {
                    "candidate_tool": tool,
                    "proposed_input": {"target": "host_a"},
                    "purpose": "Consider response",
                    "rationale": "Review findings",
                    "evidence_ids": [str(evidence.evidence_id)],
                }
            ],
        )
    )[0] == 200
    plan = a.service.checkpoint(a.c.incident_id).artifacts.response_plan
    status, raw = await call(
        a.app,
        "POST",
        a.base + "/response-review-requests",
        {
            "proposal_id": plan.proposed_actions[0].proposal_id,
            "reviewer_id": "reviewer-alice",
            "disposition": "ready_for_promotion",
            "reason": "Checked",
            "blocker_responses": [
                {
                    "blocking_reason": r,
                    "resolution": "addressed_for_promotion",
                    "response": "Human considered; tool approval remains required",
                }
                for r in plan.proposed_actions[0].details.blocking_reasons
            ],
        },
        a.token,
    )
    assert status == 200, raw
    intent = ResponseReviewIntent.model_validate(raw)
    token = a.b.issue(
        HumanActionContext(
            incident_id=a.c.incident_id,
            action=HumanAction.REVIEW_RESPONSE_ACTION,
            binding_digest=content_digest(intent),
            decision_id=plan.content.basis.decision.decision_id,
        ),
        (HumanRole.RESPONDER,),
    )
    status, reviewed = await call(
        a.app, "POST", a.base + "/response-reviews", {"intent_id": str(intent.intent_id)}, token
    )
    assert status == 200, reviewed
    status, promoted = await call(
        a.app, "POST", a.base + "/promotions", {"review_id": reviewed["review_id"]}, a.token
    )
    assert status == 200, promoted
    return promoted["promoted_id"]


@pytest.mark.asyncio
async def test_create_read_start_trace_and_replays(api_case):
    a = api_case()
    identity = str(uuid4())
    assert (await call(a.app, "POST", "/incidents", {"incident_id": identity}, a.token))[0] == 200
    status, stored = await call(a.app, "GET", "/incidents/" + identity, token=a.token)
    assert status == 200 and stored["state"]["status"] == "new"
    assert (await call(a.app, "POST", "/incidents", {"incident_id": identity}, a.token))[0] == 409
    path = "/incidents/" + identity + "/workflow/start"
    assert (await call(a.app, "POST", path, token=a.token))[0] == 200
    assert (await call(a.app, "POST", path, token=a.token))[0] == 409
    saved = a.service.checkpoint(a.c.incident_id)
    body = {"run_id": str(saved.run_id), "expected_revision": saved.revision}
    path = a.base + "/workflow/step"
    assert (await call(a.app, "POST", path, body, a.token))[0] == 200
    assert (await call(a.app, "POST", path, body, a.token))[0] == 409
    status, trace = await call(a.app, "GET", a.base + "/trace", token=a.token)
    assert status == 200 and len(trace["entries"]) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("write", [False, True])
async def test_real_governance_execution_lifecycle(api_case, write):
    a = api_case(severities=("high",) if write else ("info",))
    identity = await promote(a, write)
    status, waiting = await step(a, promoted_id=identity)
    assert status == 200
    if write:
        assert waiting["waiting_for_human"] and a.c.mocks["test_response"].call_count == 0
        status, pending = await call(
            a.app,
            "POST",
            a.base + "/approval-requests",
            {"promoted_id": identity, "reason": "Explicit request"},
            a.token,
        )
        assert status == 200
        value = a.service.promoted(a.c.incident_id, identity)
        intent = a.c.bridge.approval_intent(value, __import__("uuid").UUID(pending["approval_id"]))
        token = a.b.issue(
            HumanActionContext(
                incident_id=a.c.incident_id,
                action=HumanAction.APPROVE_PROMOTED_TOOL,
                binding_digest=content_digest(intent),
                decision_id=a.service.checkpoint(a.c.incident_id).artifacts.decision.decision_id,
            ),
            (HumanRole.APPROVER,),
        )
        body = {"promoted_id": identity, "approval_id": pending["approval_id"]}
        assert (await call(a.app, "POST", a.base + "/approvals", body, token))[0] == 200
        assert (await call(a.app, "POST", a.base + "/approvals", body, token))[0] != 200
        assert (await step(a, promoted_id=identity, approval_id=pending["approval_id"]))[0] == 200
    assert (await step(a, execute=True))[1]["next_step"] == "evaluate"
    assert (await step(a))[1]["terminal"]
    assert a.c.llm.calls == 1


@pytest.mark.asyncio
async def test_review_permission_confirmation_and_resume(api_case):
    a = api_case()
    await decision(a)
    assert (await step(a))[1]["waiting_for_human"]
    assert (await review(a, roles=()))[0] == 403
    status, record, body, token = await review(a)
    assert status == 200
    assert (await call(a.app, "POST", a.base + "/reviews", body, token))[0] == 403
    assert (await step(a, review_id=record["review_id"]))[0] == 200
    assert a.c.llm.calls == 1


@pytest.mark.asyncio
async def test_restart_and_concurrent_resume(api_case):
    a = api_case()
    await decision(a)
    # Every application step uses a new runtime restored from SQLite.
    saved = a.service.checkpoint(a.c.incident_id)
    body = {"run_id": str(saved.run_id), "expected_revision": saved.revision}
    results = await asyncio.gather(
        *[call(a.app, "POST", a.base + "/workflow/resume", body, a.token) for _ in range(2)]
    )
    assert sorted(r[0] for r in results) == [200, 409]
    assert a.c.llm.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,body,expected",
    [
        ("/incidents/not-a-uuid", {}, 422),
        ("/incidents", {"incident_id": str(uuid4()), "status": "closed"}, 422),
        ("/incidents", {"incident_id": str(uuid4()), "role": "admin"}, 422),
        ("/incidents", {"incident_id": str(uuid4()), "evidence": []}, 422),
    ],
)
async def test_invalid_body(api_case, path, body, expected):
    a = api_case()
    assert (await call(a.app, "POST", path, body, a.token))[0] == expected


@pytest.mark.asyncio
async def test_default_deny_and_forged_identity(api_case):
    a = api_case()
    app = SOCApplication(lambda: a.service)
    assert (await call(app, "GET", a.base, token="admin"))[0] == 401
    assert (await call(a.app, "GET", a.base, token="admin"))[0] == 401
    a.access.denied = True
    assert (await call(a.app, "GET", a.base, token=a.token))[0] == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,status", [(RuntimeError("SECRET"), 500), (CommitOutcomeUnknown("SECRET"), 503)]
)
async def test_internal_error_sanitization(api_case, monkeypatch, error, status):
    a = api_case()

    def fail(*args):
        raise error

    monkeypatch.setattr(a.service, "incident", fail)
    result = await call(a.app, "GET", a.base, token=a.token)
    assert result[0] == status and "SECRET" not in str(result)


@pytest.mark.asyncio
async def test_foreign_review_and_stale_snapshot(api_case):
    a, other = api_case(), api_case()
    await decision(a)
    _, record, _, _ = await review(a)
    assert (await step(other, review_id=record["review_id"]))[0] == 404
    saved = a.service.checkpoint(a.c.incident_id)
    state = a.c.store.load(a.c.incident_id)
    from soc_agent.state import Evidence
    from soc_agent.state.evidence import utc_now

    a.c.store.append_evidence(
        state.anchor,
        Evidence(
            incident_id=a.c.incident_id,
            source="test",
            summary="new",
            raw_data="{}",
            observed_at=utc_now(),
        ),
    )
    body = {"run_id": str(saved.run_id), "expected_revision": saved.revision}
    assert (await call(a.app, "POST", a.base + "/workflow/resume", body, a.token))[0] == 409


def test_explicit_startup(tmp_path):
    store = open_store(tmp_path / "api.sqlite", create=True)
    assert open_store(store.database.path).store_id == store.store_id


@pytest.mark.asyncio
async def test_uncertain_restart_reconciliation(api_case):
    from soc_agent.execution.durable import ReconciliationRequest

    a = api_case(responses=[TimeoutError("private remote error")])
    identity = await promote(a)
    assert (await step(a, promoted_id=identity))[0] == 200
    status, outcome = await step(a, execute=True)
    assert status == 200 and outcome["next_step"] == "recover"
    assert outcome["failure"] == "execution_uncertain"
    a.app = SOCApplication(
        lambda: a.service, provider=a.b.provider, provider_id="test-identity", access=a.access
    )
    for _ in range(2):
        assert (await step(a, execute=True))[1]["next_step"] == "recover"
    assert a.c.mocks["inspect_logs"].call_count == 1
    saved = a.service.checkpoint(a.c.incident_id)
    record = a.c.executor.store.load(saved.artifacts.execution_intent_id)
    request = ReconciliationRequest(
        execution_intent_id=record.intent.execution_intent_id,
        incident_id=a.c.incident_id,
        expected_revision=record.revision,
        outcome="confirmed_succeeded",
        reason="External test confirmation",
        references=("ticket",),
    )
    assert (
        await call(
            a.app, "POST", a.base + "/reconciliation", request.model_dump(mode="json"), a.token
        )
    )[0] == 403
    token = a.b.issue(
        HumanActionContext(
            incident_id=a.c.incident_id,
            action=HumanAction.RECONCILE_EXECUTION,
            binding_digest=content_digest(request),
            decision_id=saved.artifacts.decision.decision_id,
        ),
        (HumanRole.APPROVER,),
    )
    assert (
        await call(
            a.app, "POST", a.base + "/reconciliation", request.model_dump(mode="json"), token
        )
    )[0] == 200
    assert (await step(a))[1]["next_step"] == "evaluate"
    assert (await step(a))[1]["terminal"]
    assert a.c.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_policy_deny_before_invocation(api_case):
    from soc_agent.policy import PolicyDecision

    a = api_case()
    identity = await promote(a)
    assert (await step(a, promoted_id=identity))[0] == 200
    a.c.policy.override = PolicyDecision.DENY
    status, result = await step(a, execute=True)
    assert status == 200 and result["failure"] == "execution_failed"
    assert a.c.mocks["inspect_logs"].call_count == 0


@pytest.mark.asyncio
async def test_wrong_human_confirmation_and_protected_step_input(api_case):
    a = api_case()
    await decision(a)
    _, request = await call(a.app, "POST", a.base + "/review-requests", token=a.token)
    status, _ = await call(
        a.app,
        "POST",
        a.base + "/reviews",
        {
            "request_id": request["review_request_id"],
            "reviewer_id": "reviewer-alice",
            "outcome": "state_change_may_be_proposed",
            "reason": "No exact confirmation",
        },
        a.token,
    )
    assert status == 403
    saved = a.service.checkpoint(a.c.incident_id)
    before = a.c.store.load(a.c.incident_id)
    status, _ = await call(
        a.app,
        "POST",
        a.base + "/workflow/step",
        {
            "run_id": str(saved.run_id),
            "expected_revision": saved.revision,
            "status": "closed",
            "approved": True,
        },
        a.token,
    )
    assert status == 422 and a.c.store.load(a.c.incident_id) == before
    assert a.service.checkpoint(a.c.incident_id) == saved


@pytest.mark.asyncio
async def test_waiting_survives_new_application_without_reanalysis(api_case):
    a = api_case()
    await decision(a)
    assert (await step(a))[1]["waiting_for_human"]
    a.app = SOCApplication(
        lambda: a.service, provider=a.b.provider, provider_id="test-identity", access=a.access
    )
    assert (await call(a.app, "GET", a.base + "/workflow", token=a.token))[1]["waiting_for_human"]
    assert (await step(a))[1]["waiting_for_human"]
    assert a.c.llm.calls == 1


@pytest.mark.asyncio
async def test_not_found_and_no_patch(api_case):
    a = api_case()
    assert (await call(a.app, "GET", f"/incidents/{uuid4()}", token=a.token))[0] == 404
    assert (await call(a.app, "PATCH", a.base, {"severity": "critical"}, a.token))[0] == 405
