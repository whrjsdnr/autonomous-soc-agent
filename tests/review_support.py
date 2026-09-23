"""Test-only external human confirmation boundary; not production authentication."""

from uuid import uuid4

from soc_agent.review import (
    HumanAction,
    HumanAuthorizationDenied,
    HumanReviewService,
    ReviewOutcome,
    VerifiedHumanAction,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewIntent


class HumanConfirmations:
    """Explicitly recorded, one-use confirmations for exact purpose and payload.

    Fixture setup represents a trusted authenticated human channel. Production must
    provide real authentication, human-presence/intent confirmation and RBAC instead.
    """

    def __init__(self):
        self.confirmations = {}

    def confirm(self, *, subject, action, digest):
        if subject not in ("reviewer-alice", "approver-bob"):
            raise HumanAuthorizationDenied("Subject is not an authorized test human")
        if action == HumanAction.AUTHORIZE_STATE_CHANGE and subject != "approver-bob":
            raise HumanAuthorizationDenied("Human lacks state authorization permission")
        token = str(uuid4())
        self.confirmations[token] = VerifiedHumanAction(
            subject_id=subject, action=action, binding_digest=digest
        )
        return token

    def verify(self, *, credential, action, binding_digest):
        confirmation = self.confirmations.pop(credential, None)
        if confirmation is None or (confirmation.action, confirmation.binding_digest) != (
            action,
            binding_digest,
        ):
            raise HumanAuthorizationDenied("Missing, replayed or unbound human confirmation")
        return confirmation


def record_review(
    service: HumanReviewService, authority, request, outcome=ReviewOutcome.CHANGE_ELIGIBLE
):
    intent = ReviewIntent(
        review_request_id=request.review_request_id,
        target=request.target,
        reviewer_id="reviewer-alice",
        outcome=outcome,
        reason="Reviewed evidence and uncertainties",
    )
    token = authority.confirm(
        subject=intent.reviewer_id, action=HumanAction.RECORD_REVIEW, digest=content_digest(intent)
    )
    return service.record_review(
        request,
        reviewer_id=intent.reviewer_id,
        outcome=outcome,
        reason=intent.reason,
        credential=token,
    )


def authorize(service, authority, request, review):
    token = authority.confirm(
        subject="approver-bob",
        action=HumanAction.AUTHORIZE_STATE_CHANGE,
        digest=content_digest(request),
    )
    return service.authorize_change(request, review, credential=token)
