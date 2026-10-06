"""Trusted human-only, request-specific confirmed terminal decisions; then STOP."""

from soc_agent.improvement_review.models import (
    ImprovementReviewRecord,
    ImprovementReviewRequest,
    ReviewSubmission,
    record_identity,
    require_decision,
)
from soc_agent.improvement_review.store import ImprovementReviewStore
from soc_agent.review.authentication import (
    AuthenticationProvider,
    HumanActionContext,
    HumanPermissionVerifier,
    ProviderHumanAuthority,
)
from soc_agent.review.authority import HumanAction
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.validation import checked


def review_context(
    request: ImprovementReviewRequest, submission: ReviewSubmission
) -> HumanActionContext:
    # Exact request + decision + reason + note are all confirmed. No caller role claims.
    if submission.review_request.identity != request.review_request_id or (
        submission.review_request.digest != content_digest(request.content)
    ):
        raise StoredDataError("Review submission request digest mismatch")
    return HumanActionContext(
        incident_id=request.content.authorization_incident,
        action=HumanAction.REVIEW_IMPROVEMENT_CANDIDATE,
        binding_digest=submission.digest,
        decision_id=None,
    )


class ImprovementReviewService:
    def __init__(
        self,
        store: ImprovementReviewStore,
        *,
        provider: AuthenticationProvider,
        provider_id: str,
        permissions: HumanPermissionVerifier,
    ) -> None:
        self.store = store
        self._provider = provider
        self._provider_id = provider_id
        self._permissions = permissions
        self._consumer = SQLiteConfirmationConsumer(store.database)

    def submit(self, submission: ReviewSubmission, *, credential: str) -> ImprovementReviewRecord:
        submission = checked(ReviewSubmission, submission)
        with self.store.database.transaction() as connection:
            request = self.store._request(
                connection,
                connection.execute(
                    "SELECT * FROM improvement_review_requests WHERE id=?",
                    (submission.review_request.identity,),
                ).fetchone(),
            )
            context = review_context(request, submission)
            require_decision(request, submission.decision)
            authority = ProviderHumanAuthority(
                provider=self._provider,
                provider_id=self._provider_id,
                permissions=self._permissions,
                resolve_context=lambda action, digest: context,
                confirmation_consumer=self._consumer.for_transaction(
                    self.store.database.store_id, connection
                ),
            )
            principal = authority.authenticate_context(credential=credential, context=context)
            existing = connection.execute(
                "SELECT * FROM improvement_review_records WHERE request_id=?",
                (request.review_request_id,),
            ).fetchone()
            if existing is not None:
                old = self.store._record(connection, existing)
                v = old.verification
                if old.submission == submission and (v.provider_id, v.subject_id, v.session_id) == (
                    principal.provider_id,
                    principal.subject_id,
                    principal.session_id,
                ):
                    return old  # Read committed result; never consume another confirmation.
                raise HumanAuthorizationDenied("Review request already has a terminal decision")
            authority.verify(
                credential=credential, action=context.action, binding_digest=submission.digest
            )
            (verification,) = authority.verification_records()
            if (verification.provider_id, verification.subject_id, verification.session_id) != (
                principal.provider_id,
                principal.subject_id,
                principal.session_id,
            ):
                raise StoredDataError("Provider principal changed during improvement review")
            value = ImprovementReviewRecord(
                review_record_id=record_identity(submission, verification),
                submission=submission,
                snapshot=request.content,
                verification=verification,
            )
            connection.execute(
                "INSERT INTO improvement_review_records VALUES (?,?,?,?,?)",
                (
                    value.review_record_id,
                    request.review_request_id,
                    request.content.binding.source.candidate.identity,
                    ledger.serialize(value),
                    content_digest(value),
                ),
            )
            return value
