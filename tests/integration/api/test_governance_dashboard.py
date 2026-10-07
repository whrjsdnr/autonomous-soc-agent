"""Native governance UX delegates to real durable services and trusted test identity."""

import json
from datetime import timedelta
from urllib.parse import urlencode
from uuid import uuid4

import pytest

from soc_agent.api import SOCApplication
from soc_agent.api.dashboard.governance_commands import GovernanceUX, context_for
from soc_agent.api.dashboard.governance_models import GovernanceDomain, ReviewDecisionInput
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewOutcome, SeverityChange
from soc_agent.review.persistence import PersistentHumanReviewService
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.state import Severity
from soc_agent.state.evidence import utc_now
from tests.integration.api.conftest import step
from tests.integration.api.test_dashboard import dump, fail
from tests.unit.confirmations.conftest import authority_for

ORIGIN = "https://soc.example.test"
pytestmark = pytest.mark.asyncio


async def http(
    a,
    path="/dashboard/governance",
    *,
    method="GET",
    body=None,
    token=None,
    html=False,
    headers=None,
    form=False,
    raw=None,
):
    output = []
    auth = a.token if token is None else token
    metadata = [(b"accept", b"text/html" if html else b"application/json")]
    if auth:
        metadata.append((b"authorization", f"Bearer {auth}".encode()))
    if method == "POST":
        metadata += [
            (b"origin", ORIGIN.encode()),
            (b"host", b"soc.example.test"),
            (
                b"content-type",
                b"application/x-www-form-urlencoded" if form else b"application/json",
            ),
        ]
    for key, value in (headers or {}).items():
        metadata = [(k, v) for k, v in metadata if k != key]
        if value is not None:
            metadata.append((key, value))
    payload = (
        raw
        if raw is not None
        else (urlencode(body or {}).encode() if form else json.dumps(body or {}).encode())
    )

    async def receive():
        return {"type": "http.request", "body": payload}

    async def send(value):
        output.append(value)

    await a.app(
        {"type": "http", "method": method, "path": path, "headers": metadata}, receive, send
    )
    text = output[1]["body"].decode()
    return output[0]["status"], text if html else json.loads(text), dict(output[0]["headers"])


async def pending(api_case):
    a = api_case()
    a.app.dashboard_origin = ORIGIN
    a.service.governance_confirmation_preview = lambda credential, principal, context: (
        a.b.provider.confirmations[credential]
    )
    for _ in range(8):
        if a.service.checkpoint(a.c.incident_id).artifacts.decision is not None:
            break
        status, _ = await step(a)
        assert status == 200
    request = a.service.review_request(a.c.incident_id)
    path = (
        f"/dashboard/governance/incidents/{a.c.incident_id}/"
        f"incident-reviews/{request.review_request_id}"
    )
    return a, request, path


def decision_token(a, request, outcome=ReviewOutcome.ACKNOWLEDGED, roles=(HumanRole.ADMIN,)):
    body = ReviewDecisionInput(
        expected_request_digest=content_digest(request),
        outcome=outcome,
        reason="Explicit human review",
    )
    source = GovernanceUX(a.service).source(
        a.c.incident_id, GovernanceDomain.INCIDENT_REVIEW, request.review_request_id
    )
    principal = a.b.provider.principals[a.token]
    context = context_for(source, principal, body)
    token = a.b.issue(context, roles)
    return token, body.model_dump(mode="json")


def final_fields(preview, body):
    return {
        **body,
        "confirmation_id": preview["confirmation_id"],
        "expected_confirmation_digest": preview["context"]["binding_digest"],
    }


async def authorize_pending(api_case):
    a, review_request, review_path = await pending(api_case)
    token, body = decision_token(a, review_request, ReviewOutcome.CHANGE_ELIGIBLE)
    status, preview, _ = await http(
        a, review_path + "/preview", method="POST", body=body, token=token
    )
    assert status == 200
    status, result, _ = await http(
        a, review_path + "/decision", method="POST", body=final_fields(preview, body), token=token
    )
    assert status == 200
    review = next(r for r in a.service.reviews.reviews() if str(r.review_id) == result["record_id"])
    request = a.service.reviews.propose_change(
        review,
        changes=(
            SeverityChange(
                before=a.c.store.load(a.c.incident_id).state.severity, after=Severity.HIGH
            ),
        ),
        reason="Explicit state proposal",
    )
    source = GovernanceUX(a.service).source(
        a.c.incident_id, GovernanceDomain.STATE_AUTHORIZATION, request.request_id
    )
    context = context_for(source, a.b.provider.principals[token])
    auth_token = a.b.issue(context, (HumanRole.ADMIN,))
    path = (
        f"/dashboard/governance/incidents/{a.c.incident_id}/"
        f"state-authorizations/{request.request_id}"
    )
    return a, request, path, auth_token, {"expected_request_digest": content_digest(request)}


async def test_inbox_empty_auth_access_and_native_shell(api_case):
    a = api_case()
    before = dump(a.c.store)
    status, page, headers = await http(a, html=True)
    assert status == 200 and "No accessible pending" in page
    assert "Human Governance Inbox" in page and "UNKNOWN" not in page  # no invented empty risk
    assert "form-action 'self'" in headers[b"content-security-policy"].decode()
    assert (await http(a, token=""))[0] == 401
    a.access.denied = True
    assert (await http(a))[0] == 403
    assert dump(a.c.store) == before


async def test_request_render_unknown_basis_and_read_only_preview(api_case, monkeypatch):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request)
    before = dump(a.c.store)
    monkeypatch.setattr(a.b.provider, "confirm", fail)
    status, inbox, _ = await http(a, token=token)
    assert status == 200 and len(inbox["actions"]) == 1
    assert inbox["actions"][0]["risk"] == "UNKNOWN"
    assert inbox["actions"][0]["impact"] == "UNKNOWN"
    assert inbox == (await http(a, token=token))[1]
    status, page, _ = await http(a, path, token=token, html=True)
    assert status == 200 and "Current Incident State" in page and "Proposed State" in page
    assert "state_change_may_be_proposed" in page and 'value="APPROVE"' not in page
    status, preview, _ = await http(a, path + "/preview", method="POST", body=body, token=token)
    assert status == 200 and preview["subject_id"] == "reviewer-alice"
    assert preview["context"]["binding_digest"] == a.b.provider.confirmations[token].binding_digest
    assert dump(a.c.store) == before and not a.b.provider.used


@pytest.mark.parametrize("outcome", tuple(ReviewOutcome))
async def test_actual_review_decisions_record_only_and_replay_conflicts(
    api_case, monkeypatch, outcome
):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request, outcome)
    saved, incident = a.service.checkpoint(a.c.incident_id), a.c.store.load(a.c.incident_id)
    llm_calls = a.c.llm.calls
    tool_calls = {name: tool.call_count for name, tool in a.c.mocks.items()}
    monkeypatch.setattr(a.service, "runtime_factory", fail)
    monkeypatch.setattr(a.service.reviews, "apply", fail)
    monkeypatch.setattr(a.service, "promote", fail)
    monkeypatch.setattr(a.service, "reconcile", fail)
    status, preview, _ = await http(a, path + "/preview", method="POST", body=body, token=token)
    assert status == 200
    final = final_fields(preview, body)
    status, result, _ = await http(a, path + "/decision", method="POST", body=final, token=token)
    assert status == 200 and result["decision"] == outcome.value and not result["state_applied"]
    records = a.service.reviews.reviews()
    assert a.c.llm.calls == llm_calls
    assert {name: tool.call_count for name, tool in a.c.mocks.items()} == tool_calls
    assert len(records) == 1 and records[0].reviewer_id == "reviewer-alice"
    receipt = SQLiteConfirmationConsumer(a.c.store.database).load(
        "test-identity", preview["confirmation_id"]
    )
    assert (
        receipt.consumed
        and receipt.verification.context.binding_digest == preview["context"]["binding_digest"]
    )
    assert (
        a.service.checkpoint(a.c.incident_id) == saved
        and a.c.store.load(a.c.incident_id) == incident
    )
    before = dump(a.c.store)
    assert (await http(a, path + "/decision", method="POST", body=final, token=token))[0] == 409
    a.service.reviews = PersistentHumanReviewService(
        store=a.c.store,
        authority=authority_for(a.b, SQLiteConfirmationConsumer(a.c.store.database)),
    )
    assert (await http(a, path + "/decision", method="POST", body=final, token=token))[0] == 409
    assert dump(a.c.store) == before


async def test_state_authorization_is_not_application_or_tool_approval(api_case, monkeypatch):
    a, request, path, token, body = await authorize_pending(api_case)
    incident = a.c.store.load(a.c.incident_id)
    monkeypatch.setattr(a.service.reviews, "apply", fail)
    monkeypatch.setattr(a.service, "approve", fail)
    monkeypatch.setattr(a.service, "runtime_factory", fail)
    status, page, _ = await http(a, path, token=token, html=True)
    assert (
        status == 200 and "STATE CHANGE AUTHORIZATION" in page and "severity: info → high" in page
    )
    before = dump(a.c.store)
    status, preview, _ = await http(a, path + "/preview", method="POST", body=body, token=token)
    assert status == 200 and dump(a.c.store) == before
    final = final_fields(preview, body)
    status, result, _ = await http(a, path + "/decision", method="POST", body=final, token=token)
    assert status == 200 and result["decision"] == "state_change_authorization_issued"
    assert a.c.store.load(a.c.incident_id) == incident and not result["state_applied"]
    assert len(a.service.reviews.authorizations()) == 1
    assert (await http(a, path + "/decision", method="POST", body=final, token=token))[0] == 409


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject_id", "other-human"),
        ("session_id", "other-session"),
        ("action", HumanAction.APPROVE_PROMOTED_TOOL),
        ("binding_digest", "c" * 64),
        ("expires_at", utc_now() - timedelta(seconds=1)),
    ],
)
async def test_exact_confirmation_identity_session_purpose_digest_expiry(api_case, field, value):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request)
    confirmation = a.b.provider.confirmations[token]
    a.b.provider.confirmations[token] = confirmation.model_copy(update={field: value})
    before = dump(a.c.store)
    assert (await http(a, path + "/preview", method="POST", body=body, token=token))[0] == 403
    assert dump(a.c.store) == before and not a.b.provider.used


async def test_permission_and_object_filtering_no_body_elevation(api_case):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request, roles=(HumanRole.RESPONDER,))
    assert (await http(a, token=token))[1]["actions"] == []
    assert (await http(a, path, token=token))[0] == 403
    token, body = decision_token(a, request)
    before = dump(a.c.store)
    assert (
        await http(a, path + "/preview", method="POST", body={**body, "role": "admin"}, token=token)
    )[0] == 422
    original = a.access.require_access

    def access(principal, incident, operation):
        if incident == a.c.incident_id:
            raise ValueError("object denied")
        original(principal, incident, operation)

    a.access.require_access = access
    assert (await http(a, token=token))[1]["actions"] == []
    assert (await http(a, path + "/preview", method="POST", body=body, token=token))[0] == 403
    assert dump(a.c.store) == before


@pytest.mark.parametrize(
    "headers,status",
    [
        ({b"origin": b"https://attacker.test"}, 403),
        ({b"host": b"attacker.test"}, 403),
        ({b"origin": None}, 403),
        ({b"sec-fetch-site": b"cross-site"}, 403),
        ({b"content-type": b"text/plain"}, 415),
    ],
)
async def test_browser_post_origin_host_and_content_type(api_case, headers, status):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request)
    before = dump(a.c.store)
    assert (
        await http(a, path + "/preview", method="POST", body=body, token=token, headers=headers)
    )[0] == status
    assert dump(a.c.store) == before


async def test_form_two_step_html_escape_and_no_credential_dump(api_case):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request)
    body["reason"] = '<img src=x onerror="attack()">'
    source = GovernanceUX(a.service).source(
        a.c.incident_id, GovernanceDomain.INCIDENT_REVIEW, request.review_request_id
    )
    context = context_for(
        source, a.b.provider.principals[token], ReviewDecisionInput.model_validate(body)
    )
    token = a.b.issue(context, (HumanRole.ADMIN,))
    status, page, _ = await http(
        a, path + "/preview", method="POST", body=body, token=token, html=True, form=True
    )
    assert (
        status == 200
        and "Step 2 of 2" in page
        and "Confirm Acknowledge Without Authorization" in page
    )
    assert "&lt;img" in page and "<img" not in page and token not in page
    assert 'name="role"' not in page and 'name="reviewer_id"' not in page
    final = {
        **body,
        "confirmation_id": a.b.provider.confirmations[token].confirmation_id,
        "expected_confirmation_digest": context.binding_digest,
    }
    status, page, _ = await http(
        a, path + "/decision", method="POST", body=final, token=token, html=True, form=True
    )
    assert status == 200 and "Governance Decision Recorded" in page and "State Applied: NO" in page


async def test_stale_cross_incident_invalid_payload_and_confirmation_reference(api_case):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request)
    before = dump(a.c.store)
    bad = {**body, "expected_request_digest": "d" * 64}
    assert (await http(a, path + "/preview", method="POST", body=bad, token=token))[0] == 409
    cross = path.replace(str(a.c.incident_id), str(uuid4()))
    assert (await http(a, cross, token=token))[0] == 404
    assert (await http(a, path + "/decision", token=token))[0] == 405
    assert (await http(a, path + "/preview", method="POST", raw=b"{broken", token=token))[0] == 422
    assert (
        await http(
            a,
            path + "/preview",
            method="POST",
            body={**body, "reason": "password=secret"},
            token=token,
        )
    )[0] == 422
    status, preview, _ = await http(a, path + "/preview", method="POST", body=body, token=token)
    assert status == 200
    final = {**final_fields(preview, body), "confirmation_id": "unrelated-reference"}
    assert (await http(a, path + "/decision", method="POST", body=final, token=token))[0] == 403
    assert dump(a.c.store) == before


async def test_preview_optional_and_no_implicit_confirmation_issuance(api_case):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request)
    a.service.governance_confirmation_preview = None
    status, page, _ = await http(a, path, token=token, html=True)
    assert status == 200 and "READ ONLY" in page and "<form" not in page
    assert (await http(a, path + "/preview", method="POST", body=body, token=token))[0] == 403
    a.app.dashboard_origin = None
    assert (await http(a, path + "/decision", method="POST", body=body, token=token))[0] == 403


async def test_origin_configuration_rejects_ambiguous_untrusted_values():
    for origin in ("https://host/path", "https://user:password@host", "https://host?x=y", "host"):
        with pytest.raises(ValueError):
            SOCApplication(lambda: None, dashboard_origin=origin)


async def test_stale_incident_snapshot_is_not_rebased(api_case):
    a, change, path, token, body = await authorize_pending(api_case)
    old_request = a.service.review_request(a.c.incident_id)
    old_token, old_body = decision_token(a, old_request)
    old_path = (
        f"/dashboard/governance/incidents/{a.c.incident_id}/"
        f"incident-reviews/{old_request.review_request_id}"
    )
    status, preview, _ = await http(a, path + "/preview", method="POST", body=body, token=token)
    assert status == 200
    status, result, _ = await http(
        a, path + "/decision", method="POST", body=final_fields(preview, body), token=token
    )
    assert status == 200
    authorization = next(
        r
        for r in a.service.reviews.authorizations()
        if str(r.authorization_id) == result["record_id"]
    )
    review = next(r for r in a.service.reviews.reviews() if r.review_id == change.review_id)
    a.service.reviews.apply(
        a.c.store.load(a.c.incident_id).state,
        a.service.checkpoint(a.c.incident_id).artifacts.decision,
        review,
        change,
        authorization,
    )
    before = dump(a.c.store)
    status, view, _ = await http(a, old_path, token=old_token)
    assert status == 200 and view["status"] == "STALE SNAPSHOT" and not view["actionable"]
    assert (await http(a, old_path + "/preview", method="POST", body=old_body, token=old_token))[
        0
    ] == 409
    assert dump(a.c.store) == before


async def test_source_integrity_failure_not_presented_as_confirmation_retry(api_case):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request)
    with a.c.store.database.transaction() as connection:
        connection.execute(
            "UPDATE review_requests SET digest=? WHERE id=?",
            ("0" * 64, str(request.review_request_id)),
        )
    before = dump(a.c.store)
    status, response, _ = await http(a, path + "/preview", method="POST", body=body, token=token)
    assert status == 503 and response == {"error": "persistence_unavailable"}
    assert dump(a.c.store) == before and not a.b.provider.used


async def test_consumed_confirmation_cannot_authorize_another_pending_request(api_case):
    a, request, path = await pending(api_case)
    token, body = decision_token(a, request)
    status, preview, _ = await http(a, path + "/preview", method="POST", body=body, token=token)
    assert status == 200
    assert (
        await http(
            a, path + "/decision", method="POST", body=final_fields(preview, body), token=token
        )
    )[0] == 200
    second = a.service.review_request(a.c.incident_id)
    second_token, second_body = decision_token(a, second)
    second_path = (
        f"/dashboard/governance/incidents/{a.c.incident_id}/incident-reviews/"
        f"{second.review_request_id}"
    )
    a.b.provider.confirmations[second_token] = a.b.provider.confirmations[second_token].model_copy(
        update={"confirmation_id": preview["confirmation_id"]}
    )
    before = dump(a.c.store)
    assert (
        await http(a, second_path + "/preview", method="POST", body=second_body, token=second_token)
    )[0] == 409
    assert dump(a.c.store) == before
