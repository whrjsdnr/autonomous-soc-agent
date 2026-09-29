from uuid import uuid4

import pytest

from soc_agent.execution.durable import Lifecycle, ReconciledOutcome, ReconciliationRequest
from soc_agent.execution.durable.errors import ClaimConflict
from soc_agent.review.authority import HumanAction
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest


def uncertain(durable):
    store, record, _, _ = durable
    running = store.transition(
        store.claim(record.intent.execution_intent_id, claimant="worker"), Lifecycle.EXECUTING
    )
    return store.transition(running, Lifecycle.UNCERTAIN, reason="Lost response")


def request_for(record, outcome):
    return ReconciliationRequest(
        execution_intent_id=record.intent.execution_intent_id,
        incident_id=record.intent.binding.incident_id,
        expected_revision=record.revision,
        outcome=outcome,
        reason="Operator inspected external record",
        references=("external-ticket:123",),
    )


@pytest.mark.parametrize("outcome", list(ReconciledOutcome))
def test_trusted_reconciliation_never_retries(durable, outcome):
    store, _, _, workflow = durable
    record = uncertain(durable)
    request = request_for(record, outcome)
    authority = workflow[6]
    token = authority.confirm(
        subject="reviewer-alice",
        action=HumanAction.RECONCILE_EXECUTION,
        digest=content_digest(request),
    )
    result = store.reconcile(request, credential=token, authority=authority)
    expected = {
        ReconciledOutcome.CONFIRMED_SUCCEEDED: Lifecycle.SUCCEEDED,
        ReconciledOutcome.CONFIRMED_FAILED: Lifecycle.FAILED,
        ReconciledOutcome.UNRESOLVED: Lifecycle.UNCERTAIN,
    }[outcome]
    assert result.state == expected
    assert (
        store.events(record.intent.execution_intent_id)[-1].reconciliation.actor == "reviewer-alice"
    )
    with pytest.raises(ClaimConflict):
        store.claim(record.intent.execution_intent_id, claimant="worker")


def test_reconciliation_default_denial(durable):
    store, _, _, _ = durable
    request = request_for(uncertain(durable), ReconciledOutcome.CONFIRMED_SUCCEEDED)
    with pytest.raises(HumanAuthorizationDenied):
        store.reconcile(request, credential="admin")


@pytest.mark.parametrize("substitution", ["incident", "execution", "revision", "outcome"])
def test_reconciliation_forgery(durable, substitution):
    store, _, _, workflow = durable
    request = request_for(uncertain(durable), ReconciledOutcome.CONFIRMED_SUCCEEDED)
    authority = workflow[6]
    token = authority.confirm(
        subject="reviewer-alice",
        action=HumanAction.RECONCILE_EXECUTION,
        digest=content_digest(request),
    )
    updates = {
        "incident": {"incident_id": uuid4()},
        "execution": {"execution_intent_id": "a" * 64},
        "revision": {"expected_revision": request.expected_revision + 1},
        "outcome": {"outcome": ReconciledOutcome.CONFIRMED_FAILED},
    }[substitution]
    with pytest.raises(HumanAuthorizationDenied):
        store.reconcile(request.model_copy(update=updates), credential=token, authority=authority)


def test_confirmed_but_cross_incident_reconciliation_rejected(durable):
    store, _, _, workflow = durable
    record = uncertain(durable)
    request = request_for(record, ReconciledOutcome.CONFIRMED_SUCCEEDED).model_copy(
        update={"incident_id": uuid4()}
    )
    authority = workflow[6]
    token = authority.confirm(
        subject="reviewer-alice",
        action=HumanAction.RECONCILE_EXECUTION,
        digest=content_digest(request),
    )
    with pytest.raises(ClaimConflict):
        store.reconcile(request, credential=token, authority=authority)
    assert store.load(record.intent.execution_intent_id) == record
