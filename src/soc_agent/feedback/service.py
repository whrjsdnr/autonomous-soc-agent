"""Authenticated human adjudication: read, validate, consume, store, audit only."""

from soc_agent.evaluation.sources import validate_sources
from soc_agent.experience.models import Experience
from soc_agent.feedback.models import AnalystFeedback, FeedbackRequest, feedback_identity
from soc_agent.feedback.store import FeedbackStore
from soc_agent.review.authentication import (
    AuthenticationProvider,
    HumanActionContext,
    HumanPermissionVerifier,
    ProviderHumanAuthority,
)
from soc_agent.review.authority import HumanAction
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.validation import checked


def feedback_context(request: FeedbackRequest, experience: Experience) -> HumanActionContext:
    """Resolve from checked sources; digest includes every label, note and source reference."""
    return HumanActionContext(
        incident_id=request.incident_id,
        action=HumanAction.SUBMIT_ANALYST_FEEDBACK,
        binding_digest=request.digest,
        decision_id=next(
            (r.identity for r in experience.content.references if r.kind == "decision"), None
        ),
        request_id=request.submission_id,
    )


class AnalystFeedbackService:
    def __init__(
        self,
        store: FeedbackStore,
        *,
        provider: AuthenticationProvider,
        provider_id: str,
        permissions: HumanPermissionVerifier,
    ) -> None:
        # Explicit trusted composition only. No default authentication provider or permissive role.
        self.store = store
        self._provider = provider
        self._provider_id = provider_id
        self._permissions = permissions
        self._consumer = SQLiteConfirmationConsumer(store.database)

    def submit(self, request: FeedbackRequest, *, credential: str) -> AnalystFeedback:
        request = checked(FeedbackRequest, request)
        with self.store.database.transaction() as connection:
            experience = self.store.validate_sources(connection, request)
            validate_sources(connection, self.store.evaluations.experiences, experience)
            context = feedback_context(request, experience)
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
            row = connection.execute(
                "SELECT * FROM analyst_feedback WHERE provider_id=? AND subject_id=? "
                "AND submission_id=?",
                (principal.provider_id, principal.subject_id, str(request.submission_id)),
            ).fetchone()
            if row is not None:
                old = self.store._decode(connection, row)
                if old.request != request or old.verification.session_id != principal.session_id:
                    raise StoredDataError("Conflicting feedback retry or session")
                # A read of the committed result, not another confirmation consumption.
                return old
            authority.verify(
                credential=credential, action=context.action, binding_digest=request.digest
            )
            (verification,) = authority.verification_records()
            if (verification.provider_id, verification.subject_id, verification.session_id) != (
                principal.provider_id,
                principal.subject_id,
                principal.session_id,
            ):
                raise StoredDataError("Provider principal changed during submission")
            value = AnalystFeedback(
                feedback_id=feedback_identity(
                    request, principal.provider_id, principal.subject_id, principal.session_id
                ),
                request=request,
                verification=verification,
            )
            self.store._insert(connection, value)
            return value
