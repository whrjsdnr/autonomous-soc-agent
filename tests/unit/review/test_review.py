from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.review_support import authorize, record_review

from soc_agent.review import (
    HumanAction,
    HumanAuthorizationDenied,
    HumanReviewService,
    ReviewError,
    ReviewOutcome,
    SeverityChange,
    StateChangeAuthorization,
    StatusChange,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.models import HumanReviewRequest, ReviewIntent, StateChangeRequest


@pytest.mark.parametrize("outcome", list(ReviewOutcome))
def test_review_alone_never_authorizes(case, outcome):
    state, decision, authority, store, service = case
    before = state.model_dump_json(), decision.model_dump_json(), store.load(state.incident_id)
    request = service.request_review(state, decision)
    review = record_review(service, authority, request, outcome)
    assert review.target.decision_id == decision.decision_id
    assert review.target.decision_rule_version == decision.rule_version
    assert review.reviewer_id == "reviewer-alice"
    assert review.additional_investigation_requested == (outcome == ReviewOutcome.INVESTIGATE)
    assert service.authorizations() == store.applications() == ()
    assert (
        state.model_dump_json(),
        decision.model_dump_json(),
        store.load(state.incident_id),
    ) == before
    with pytest.raises(ValidationError):
        review.outcome = ReviewOutcome.CHANGE_ELIGIBLE
    if outcome != ReviewOutcome.CHANGE_ELIGIBLE:
        with pytest.raises(HumanAuthorizationDenied):
            service.propose_change(
                review, changes=(SeverityChange(before="info", after="high"),), reason="test"
            )


def test_unknown_review_request_and_decision(case):
    state, decision, authority, store, service = case
    request = service.request_review(state, decision)
    for altered in (
        request.model_copy(update={"review_request_id": uuid4()}),
        request.model_copy(
            update={"target": request.target.model_copy(update={"decision_id": "0" * 64})}
        ),
    ):
        with pytest.raises(ReviewError):
            record_review(service, authority, altered)
    assert service.reviews() == ()


def test_cross_incident_decision(case):
    state, decision, authority, store, service = case
    from soc_agent.state import IncidentState

    with pytest.raises(ValueError):
        service.request_review(IncidentState(), decision)
    assert service.reviews() == ()


@pytest.mark.parametrize("identity", ["", " ", None])
def test_missing_reviewer(case, identity):
    state, decision, _, _, service = case
    request = service.request_review(state, decision)
    with pytest.raises(ValidationError):
        service.record_review(
            request,
            reviewer_id=identity,
            outcome=ReviewOutcome.ACKNOWLEDGED,
            reason="Review",
            credential="not sufficient",
        )


def test_default_deny_even_with_reviewer_string(case):
    state, decision, _, store, _ = case
    service = HumanReviewService(store=store)
    request = service.request_review(state, decision)
    with pytest.raises(HumanAuthorizationDenied):
        service.record_review(
            request,
            reviewer_id="admin",
            outcome=ReviewOutcome.CHANGE_ELIGIBLE,
            reason="Review",
            credential="admin",
        )
    assert service.reviews() == ()


def test_verified_subject_must_match_reviewer(case):
    state, decision, authority, _, service = case
    request = service.request_review(state, decision)
    intent = ReviewIntent(
        review_request_id=request.review_request_id,
        target=request.target,
        reviewer_id="reviewer-alice",
        outcome=ReviewOutcome.CHANGE_ELIGIBLE,
        reason="Review",
    )
    token = authority.confirm(
        subject="approver-bob", action=HumanAction.RECORD_REVIEW, digest=content_digest(intent)
    )
    with pytest.raises(HumanAuthorizationDenied):
        service.record_review(
            request,
            reviewer_id=intent.reviewer_id,
            outcome=intent.outcome,
            reason=intent.reason,
            credential=token,
        )


@pytest.mark.parametrize(
    "field",
    ["evidence", "observations", "hypotheses", "confidence", "policy", "approval", "registry"],
)
def test_forbidden_change_fields(prepared, field):
    *_, request, authorization = prepared
    payload = request.model_dump()
    payload["changes"] = [{"field": field, "before": "info", "after": "high"}]
    with pytest.raises(ValidationError):
        StateChangeRequest.model_validate(payload)


@pytest.mark.parametrize(
    "change",
    [
        {"field": "severity", "before": "info", "after": "extreme"},
        {"field": "status", "before": "new", "after": "open"},
        {"field": "status", "before": "new", "after": "new"},
    ],
)
def test_invalid_enum_or_noop(prepared, change):
    *_, request, authorization = prepared
    with pytest.raises(ValidationError):
        StateChangeRequest.model_validate(request.model_dump() | {"changes": [change]})


def test_before_value_and_unchecked_changes(case):
    state, decision, authority, store, service = case
    review = record_review(service, authority, service.request_review(state, decision))
    for change in (
        SeverityChange(before="low", after="high"),
        SeverityChange(before="info", after="high").model_copy(update={"after": "invalid"}),
    ):
        with pytest.raises(ValueError):
            service.propose_change(review, changes=(change,), reason="No partial proposal")
    assert store.load(state.incident_id).state == state


def test_no_permission_and_no_bound_intent(case):
    state, decision, authority, _, service = case
    review = record_review(service, authority, service.request_review(state, decision))
    request = service.propose_change(
        review, changes=(StatusChange(before="new", after="triaging"),), reason="Explicit review"
    )
    with pytest.raises(HumanAuthorizationDenied):
        authority.confirm(
            subject="reviewer-alice",
            action=HumanAction.AUTHORIZE_STATE_CHANGE,
            digest=content_digest(request),
        )
    for credential in ("approver-bob", "llm", ""):
        with pytest.raises(HumanAuthorizationDenied):
            service.authorize_change(request, review, credential=credential)
    token = authority.confirm(
        subject="approver-bob", action=HumanAction.AUTHORIZE_STATE_CHANGE, digest="0" * 64
    )
    with pytest.raises(HumanAuthorizationDenied):
        service.authorize_change(request, review, credential=token)
    assert service.authorizations() == ()


def test_review_record_and_authorization_forgery(prepared):
    state, decision, authority, store, service, review, request, authorization = prepared
    for forged in (
        None,
        authorization.model_copy(update={"authorization_id": uuid4()}),
        authorization.model_copy(update={"authorized_by": "mallory"}),
    ):
        with pytest.raises(ReviewError):
            service.apply(state, decision, review, request, forged)
    with pytest.raises(ReviewError):
        service.apply(
            state,
            decision,
            review.model_copy(update={"review_id": uuid4()}),
            request,
            authorization,
        )
    assert store.load(state.incident_id).state == state
    assert store.applications() == ()


@pytest.mark.parametrize("field", ["request_id", "review_id", "reason", "changes", "target"])
def test_authorized_request_is_exactly_bound(prepared, field):
    state, decision, _, store, service, review, request, authorization = prepared
    change = {
        "request_id": uuid4(),
        "review_id": uuid4(),
        "reason": "changed reason",
        "changes": (SeverityChange(before="info", after="critical"),),
        "target": request.target.model_copy(update={"decision_id": "0" * 64}),
    }[field]
    forged = request.model_copy(update={field: change})
    with pytest.raises(ReviewError):
        service.apply(state, decision, review, forged, authorization)
    assert store.load(state.incident_id).state == state
    assert store.applications() == ()


def test_authorization_creation_does_not_apply_and_is_immutable(prepared):
    state, decision, _, store, service, review, request, authorization = prepared
    assert store.load(state.incident_id).state == state
    assert authorization.request == request
    assert authorization.request_digest == content_digest(request)
    assert authorization.authorized_by == "approver-bob"
    assert store.applications() == ()
    for obj, field in (
        (authorization, "authorized_by"),
        (request, "reason"),
        (request.changes[0], "after"),
        (review.target.snapshot, "revision"),
    ):
        with pytest.raises(ValidationError):
            setattr(obj, field, "changed")
    assert (
        StateChangeAuthorization.model_validate_json(authorization.model_dump_json())
        == authorization
    )


def test_duplicate_review_and_authorization_rejected(prepared):
    state, decision, authority, _, service, review, request, _ = prepared
    with pytest.raises(ReviewError, match="already"):
        authorize(service, authority, request, review)
    original = service._review_requests[review.review_request_id]
    with pytest.raises(ReviewError, match="already"):
        record_review(service, authority, original)


def test_unknown_structurally_valid_review_request(case):
    state, decision, authority, _, service = case
    original = service.request_review(state, decision)
    with pytest.raises(ReviewError):
        record_review(service, authority, HumanReviewRequest(target=original.target))


@pytest.mark.parametrize("field", ["action", "binding_digest"])
def test_faulty_external_confirmation_not_accepted(case, field):
    from soc_agent.review import VerifiedHumanAction

    state, decision, authority, _, service = case
    request = service.request_review(state, decision)

    def verify(**kwargs):
        payload = {
            "subject_id": "reviewer-alice",
            "action": kwargs["action"],
            "binding_digest": kwargs["binding_digest"],
        }
        payload[field] = HumanAction.AUTHORIZE_STATE_CHANGE if field == "action" else "0" * 64
        return VerifiedHumanAction.model_validate(payload)

    authority.verify = verify
    with pytest.raises(HumanAuthorizationDenied):
        service.record_review(
            request,
            reviewer_id="reviewer-alice",
            outcome=ReviewOutcome.CHANGE_ELIGIBLE,
            reason="Review",
            credential="external",
        )
    assert service.reviews() == ()
