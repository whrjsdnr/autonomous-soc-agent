from datetime import timedelta

import pytest
from tests.unit.confirmations.conftest import authority_for

from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer


def issue(boundary, planning):
    ctx = HumanActionContext(
        incident_id=planning[0].incident_id,
        decision_id=planning[1].decision_id,
        action=HumanAction.RECORD_REVIEW,
        binding_digest="b" * 64,
    )
    return boundary.issue(ctx, (HumanRole.ADMIN,)), ctx


def verify(authority, token, ctx):
    return authority.verify(credential=token, action=ctx.action, binding_digest=ctx.binding_digest)


def test_consumption_restart_and_no_credentials(boundary, planning):
    token, ctx = issue(boundary, planning)
    verify(boundary.authority, token, ctx)
    proof = boundary.provider.confirmations[token]
    reopened = SQLiteConfirmationConsumer(SQLiteGovernanceStore(planning[3].database.path).database)
    stored = reopened.load(proof.provider_id, proof.confirmation_id)
    assert stored.consumed
    assert stored.consumed_at is not None
    assert stored.consumer_reference is not None
    assert stored.verification.context == ctx
    assert token not in stored.model_dump_json()
    boundary.provider.used.clear()  # A different provider process has no local replay memory.
    with pytest.raises(HumanAuthorizationDenied, match="durably consumed"):
        verify(authority_for(boundary, reopened), token, ctx)


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject_id", "other-human"),
        ("session_id", "other-session"),
        ("action", HumanAction.APPROVE_PROMOTED_TOOL),
        ("binding_digest", "c" * 64),
    ],
)
def test_wrong_exact_binding_rejected(boundary, planning, field, value):
    token, ctx = issue(boundary, planning)
    boundary.provider.confirmations[token] = boundary.provider.confirmations[token].model_copy(
        update={field: value}
    )
    with pytest.raises(HumanAuthorizationDenied):
        verify(boundary.authority, token, ctx)
    confirmation = boundary.provider.confirmations[token]
    consumer = SQLiteConfirmationConsumer(planning[3].database)
    assert consumer.load(confirmation.provider_id, confirmation.confirmation_id) is None


def test_expiry_rechecked_inside_transaction(boundary, planning, monkeypatch):
    token, ctx = issue(boundary, planning)
    monkeypatch.setattr(
        "soc_agent.review.persistence.confirmations.utc_now",
        lambda: boundary.now + timedelta(minutes=2),
    )
    with pytest.raises(HumanAuthorizationDenied, match="expired"):
        verify(boundary.authority, token, ctx)
    assert boundary.authority.verification_records() == ()


def test_forged_credential_never_registers_confirmation(boundary, planning):
    token, ctx = issue(boundary, planning)
    with pytest.raises(HumanAuthorizationDenied):
        verify(boundary.authority, "actor=admin", ctx)
    confirmation = boundary.provider.confirmations[token]
    assert (
        SQLiteConfirmationConsumer(planning[3].database).load(
            confirmation.provider_id, confirmation.confirmation_id
        )
        is None
    )


@pytest.mark.parametrize("change", ["identity", "session", "purpose", "incident", "digest"])
def test_same_reference_cannot_be_rebound_after_restart(boundary, planning, change):
    from uuid import uuid4

    token, ctx = issue(boundary, planning)
    verify(boundary.authority, token, ctx)
    principal = boundary.provider.principals[token]
    confirmation = boundary.provider.confirmations[token]
    if change in ("identity", "session"):
        field = "subject_id" if change == "identity" else "session_id"
        principal = principal.model_copy(update={field: "other"})
        confirmation = confirmation.model_copy(update={field: "other"})
    else:
        if change == "purpose":
            ctx = ctx.model_copy(update={"action": HumanAction.RECONCILE_EXECUTION})
        elif change == "incident":
            ctx = ctx.model_copy(update={"incident_id": uuid4(), "binding_digest": "c" * 64})
        else:
            ctx = ctx.model_copy(update={"binding_digest": "c" * 64})
        confirmation = confirmation.model_copy(
            update={"action": ctx.action, "binding_digest": ctx.binding_digest}
        )
    boundary.provider.principals[token] = principal
    boundary.provider.confirmations[token] = confirmation
    boundary.provider.used.clear()
    boundary.contexts[(ctx.action, ctx.binding_digest)] = ctx
    boundary.roles.assignments[(principal.provider_id, principal.subject_id, ctx.incident_id)] = (
        HumanRole.ADMIN,
    )
    consumer = SQLiteConfirmationConsumer(SQLiteGovernanceStore(planning[3].database.path).database)
    with pytest.raises(HumanAuthorizationDenied, match="binding changed"):
        verify(authority_for(boundary, consumer), token, ctx)
