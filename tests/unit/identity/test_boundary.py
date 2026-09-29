from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole, permission_for
from soc_agent.review.errors import HumanAuthorizationDenied


def context(action=HumanAction.RECORD_REVIEW):
    return HumanActionContext(
        incident_id=uuid4(), decision_id="a" * 64, action=action, binding_digest="b" * 64
    )


def verify(boundary, token, ctx):
    return boundary.authority.verify(
        credential=token, action=ctx.action, binding_digest=ctx.binding_digest
    )


def test_identity_immutable_and_caller_cannot_forge(boundary):
    ctx = context()
    token = boundary.issue(ctx, (HumanRole.ANALYST,))
    principal = boundary.provider.principals[token]
    with pytest.raises(ValidationError):
        principal.subject_id = "admin"
    for fake in ("admin", "actor=alice", principal, principal.model_dump_json()):
        with pytest.raises(HumanAuthorizationDenied):
            verify(boundary, fake, ctx)
    assert boundary.authority.verification_records() == ()


@pytest.mark.parametrize(
    "action,role",
    [
        (HumanAction.RECORD_REVIEW, HumanRole.ANALYST),
        (HumanAction.REVIEW_RESPONSE_ACTION, HumanRole.RESPONDER),
        (HumanAction.APPROVE_PROMOTED_TOOL, HumanRole.APPROVER),
        (HumanAction.RECONCILE_EXECUTION, HumanRole.APPROVER),
        (HumanAction.AUTHORIZE_STATE_CHANGE, HumanRole.APPROVER),
    ],
)
def test_authorized_role_and_nonsecret_provenance(boundary, action, role):
    ctx = context(action)
    token = boundary.issue(ctx, (role,))
    assert verify(boundary, token, ctx).subject_id == "reviewer-alice"
    (receipt,) = boundary.authority.verification_records()
    assert receipt.permission == permission_for(action)
    assert receipt.provider_id == "test-identity"
    assert receipt.context == ctx
    assert receipt.confirmation_id == boundary.provider.confirmations[token].confirmation_id
    assert token not in receipt.model_dump_json()
    with pytest.raises(HumanAuthorizationDenied):
        verify(boundary, token, ctx)


@pytest.mark.parametrize("roles", [(), ("superuser",), (HumanRole.ANALYST,)])
def test_unknown_or_insufficient_role(boundary, roles):
    ctx = context(HumanAction.APPROVE_PROMOTED_TOOL)
    token = boundary.issue(ctx, roles)
    with pytest.raises(HumanAuthorizationDenied):
        verify(boundary, token, ctx)
    assert boundary.provider.used == set()


@pytest.mark.parametrize(
    "field",
    [
        "subject_id",
        "session_id",
        "provider_id",
        "action",
        "binding_digest",
        "expires_at",
        "confirmed_at",
    ],
)
def test_invalid_confirmation(boundary, field):
    ctx = context()
    token = boundary.issue(ctx, (HumanRole.ANALYST,))
    replacement = {
        "subject_id": "another-human",
        "session_id": "other-session",
        "provider_id": "other",
        "action": HumanAction.APPROVE_PROMOTED_TOOL,
        "binding_digest": "c" * 64,
        "expires_at": boundary.now - timedelta(seconds=1),
        "confirmed_at": boundary.now + timedelta(seconds=1),
    }[field]
    boundary.provider.confirmations[token] = boundary.provider.confirmations[token].model_copy(
        update={field: replacement}
    )
    with pytest.raises(HumanAuthorizationDenied):
        verify(boundary, token, ctx)
    assert boundary.authority.verification_records() == ()


@pytest.mark.parametrize(
    "source,target",
    [
        (HumanAction.RECORD_REVIEW, HumanAction.APPROVE_PROMOTED_TOOL),
        (HumanAction.REVIEW_RESPONSE_ACTION, HumanAction.APPROVE_PROMOTED_TOOL),
        (HumanAction.APPROVE_PROMOTED_TOOL, HumanAction.RECONCILE_EXECUTION),
        (HumanAction.REVIEW_RESPONSE_ACTION, HumanAction.RECONCILE_EXECUTION),
    ],
)
def test_cross_purpose_even_admin_rejected(boundary, source, target):
    original = context(source)
    token = boundary.issue(original, (HumanRole.ADMIN,))
    other = original.model_copy(update={"action": target})
    boundary.contexts[(target, other.binding_digest)] = other
    with pytest.raises(HumanAuthorizationDenied):
        verify(boundary, token, other)


def test_cross_incident_request_reuse(boundary):
    original = context()
    token = boundary.issue(original, (HumanRole.ADMIN,))
    other = original.model_copy(update={"incident_id": uuid4(), "binding_digest": "c" * 64})
    boundary.contexts[(other.action, other.binding_digest)] = other
    boundary.roles.assignments[("test-identity", "reviewer-alice", other.incident_id)] = (
        HumanRole.ADMIN,
    )
    with pytest.raises(HumanAuthorizationDenied):
        verify(boundary, token, other)


@pytest.mark.parametrize("component", ["provider", "roles"])
def test_dependency_failure_never_allows(boundary, component):
    ctx = context()
    token = boundary.issue(ctx, (HumanRole.ADMIN,))
    getattr(boundary, component).failure = RuntimeError("test outage")
    with pytest.raises((HumanAuthorizationDenied, RuntimeError)):
        verify(boundary, token, ctx)
    assert boundary.authority.verification_records() == ()
