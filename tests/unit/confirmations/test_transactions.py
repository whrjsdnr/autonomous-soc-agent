import sqlite3

import pytest
from tests.unit.confirmations.conftest import authority_for
from tests.unit.confirmations.test_consumption import issue, verify

from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.models import CommitOutcomeUnknown, StorageError


@pytest.mark.parametrize("committed", [False, True])
def test_consume_commit_failure_denies_operation(boundary, planning, monkeypatch, committed):
    token, ctx = issue(boundary, planning)
    database = planning[3].database

    def fail(connection):
        if committed:
            connection.commit()
        raise sqlite3.OperationalError("test commit failure")

    monkeypatch.setattr(database, "_commit", fail)
    with pytest.raises(CommitOutcomeUnknown if committed else StorageError):
        verify(boundary.authority, token, ctx)
    assert boundary.authority.verification_records() == ()
    reopened = SQLiteConfirmationConsumer(SQLiteGovernanceStore(database.path).database)
    proof = boundary.provider.confirmations[token]
    stored = reopened.load(proof.provider_id, proof.confirmation_id)
    if committed:
        assert stored.consumed
        boundary.provider.used.clear()
        with pytest.raises(HumanAuthorizationDenied):
            verify(authority_for(boundary, reopened), token, ctx)
    else:
        assert stored is None  # Known rollback is observed, never inferred from a lost response.


def test_update_failure_rolls_back_registration(boundary, planning):
    token, ctx = issue(boundary, planning)
    with sqlite3.connect(planning[3].database.path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_consume BEFORE UPDATE ON human_confirmations "
            "BEGIN SELECT RAISE(ABORT,'test'); END"
        )
    with pytest.raises(StorageError):
        verify(boundary.authority, token, ctx)
    proof = boundary.provider.confirmations[token]
    assert (
        SQLiteConfirmationConsumer(planning[3].database).load(
            proof.provider_id, proof.confirmation_id
        )
        is None
    )


@pytest.mark.parametrize("committed", [False, True])
def test_review_and_consume_share_transaction(boundary, planning, monkeypatch, committed):
    from tests.unit.identity.test_governance import credential

    from soc_agent.review.authority import HumanAction
    from soc_agent.review.authorization import HumanRole
    from soc_agent.review.models import ReviewIntent, ReviewOutcome
    from soc_agent.review.persistence import PersistentHumanReviewService

    state, decision, _, governance, *_ = planning
    service = PersistentHumanReviewService(store=governance, authority=boundary.authority)
    request = service.request_review(state, decision)
    intent = ReviewIntent(
        review_request_id=request.review_request_id,
        target=request.target,
        reviewer_id="reviewer-alice",
        outcome=ReviewOutcome.ACKNOWLEDGED,
        reason="Test atomic consumption and review",
    )
    token = credential(
        boundary, state, decision, HumanAction.RECORD_REVIEW, intent, (HumanRole.ANALYST,)
    )
    original = governance.database._commit
    injected = False

    def failure(connection):
        nonlocal injected
        if (
            not injected
            and connection.execute("SELECT COUNT(*) FROM human_confirmations").fetchone()[0]
        ):
            injected = True
            if committed:
                connection.commit()
            raise sqlite3.OperationalError("injected review commit failure")
        original(connection)

    monkeypatch.setattr(governance.database, "_commit", failure)
    with pytest.raises(CommitOutcomeUnknown if committed else StorageError):
        service.record_review(
            request,
            reviewer_id=intent.reviewer_id,
            outcome=intent.outcome,
            reason=intent.reason,
            credential=token,
        )
    reopened = SQLiteGovernanceStore(governance.database.path)
    records = PersistentHumanReviewService(store=reopened).reviews()
    assert any(r.review_request_id == request.review_request_id for r in records) == committed
    confirmation = boundary.provider.confirmations[token]
    stored = SQLiteConfirmationConsumer(reopened.database).load(
        confirmation.provider_id, confirmation.confirmation_id
    )
    assert (stored is not None and stored.consumed) == committed
