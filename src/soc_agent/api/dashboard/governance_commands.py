"""Application adapter to existing Incident governance; never applies state or executes."""

from collections.abc import Callable
from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from soc_agent.api.dashboard.governance_models import (
    GovernanceActionView,
    GovernanceConfirmationView,
    GovernanceDomain,
    GovernanceInbox,
    GovernanceResultView,
    ReviewDecisionInput,
    SubmitReviewDecision,
    SubmitStateAuthorization,
)
from soc_agent.api.dashboard.incident_query import display_text
from soc_agent.api.service import Conflict, NotFound
from soc_agent.review.authentication import (
    AuthenticatedPrincipal,
    HumanActionContext,
    HumanConfirmation,
    ProviderHumanAuthority,
)
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import permission_for
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.models import HumanReviewRequest, ReviewIntent, ReviewOutcome
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.governance_inbox import (
    GovernancePendingSource,
    read_governance_pending,
)
from soc_agent.review.validation import checked
from soc_agent.state.evidence import utc_now

if TYPE_CHECKING:
    from soc_agent.api.service import ApplicationService

# Trusted hosting reads an existing provider-verified confirmation without issuing,
# consuming or marking human intent. No default implementation is selected.
ConfirmationPreview = Callable[[str, AuthenticatedPrincipal, HumanActionContext], HumanConfirmation]


def context_for(source: GovernancePendingSource, principal, body=None) -> HumanActionContext:
    request = source.request
    if isinstance(request, HumanReviewRequest):
        intent = ReviewIntent(
            review_request_id=request.review_request_id,
            target=request.target,
            reviewer_id=principal.subject_id,
            outcome=body.outcome if body else ReviewOutcome.ACKNOWLEDGED,
            reason=body.reason if body else "Governance inbox permission check",
        )
        return HumanActionContext(
            incident_id=request.target.incident_id,
            action=HumanAction.RECORD_REVIEW,
            binding_digest=content_digest(intent),
            decision_id=request.target.decision_id,
            request_id=request.review_request_id,
        )
    return HumanActionContext(
        incident_id=request.target.incident_id,
        action=HumanAction.AUTHORIZE_STATE_CHANGE,
        binding_digest=content_digest(request),
        decision_id=request.target.decision_id,
        request_id=request.request_id,
        review_id=request.review_id,
        changes=request.changes,
    )


def action_view(source: GovernancePendingSource, actionable: bool) -> GovernanceActionView:
    request = source.request
    is_review = isinstance(request, HumanReviewRequest)
    state = source.incident.state
    current = source.incident.anchor == request.target.snapshot
    return GovernanceActionView(
        domain=(
            GovernanceDomain.INCIDENT_REVIEW if is_review else GovernanceDomain.STATE_AUTHORIZATION
        ),
        request_id=request.review_request_id if is_review else request.request_id,
        incident_id=state.incident_id,
        request_digest=content_digest(request),
        status="ACTION REQUIRED" if current else "STALE SNAPSHOT",
        summary=(
            tuple(display_text(r) for r in source.decision.rationale)
            if is_review
            else (display_text(request.reason),)
        ),
        current_state=(f"Status: {state.status.value}", f"Severity: {state.severity.value}"),
        proposed_state=(
            ("No state change proposed by this review request",)
            if is_review
            else tuple(f"{c.field}: {c.before.value} → {c.after.value}" for c in request.changes)
        ),
        basis=(
            f"Decision: {request.target.decision_id}",
            f"Assessment: {source.decision.assessment.assessment_id}",
            f"Advisory assessment severity: {source.decision.assessment.severity.value}",
            *(f"Evidence: {i}" for i in source.decision.evidence_ids),
        ),
        required_permission=permission_for(
            HumanAction.RECORD_REVIEW if is_review else HumanAction.AUTHORIZE_STATE_CHANGE
        ).value,
        decision_options=(
            tuple(o.value for o in ReviewOutcome) if is_review else ("authorize_state_change",)
        ),
        created_at=request.created_at if is_review else None,
        actionable=actionable and current,
    )


class GovernanceUX:
    def __init__(self, service: "ApplicationService") -> None:
        self.service = service

    def authority(self) -> ProviderHumanAuthority:
        authority = self.service.reviews.authority
        if not isinstance(authority, ProviderHumanAuthority):
            raise HumanAuthorizationDenied("Durable trusted human authority required")
        consumer = authority.confirmation_consumer
        if (
            not isinstance(consumer, SQLiteConfirmationConsumer)
            or consumer.database.store_id != self.service.store.store_id
        ):
            raise HumanAuthorizationDenied("Same-repository durable confirmation consumer required")
        return authority

    def inbox(self, principal, credential, visible) -> GovernanceInbox:
        actions = []
        for source in read_governance_pending(self.service.store, visible):
            try:
                self.authority().authenticate_context(
                    credential=credential, context=context_for(source, principal)
                )
            except HumanAuthorizationDenied:
                continue
            actions.append(
                action_view(source, self.service.governance_confirmation_preview is not None)
            )
        return GovernanceInbox(
            actions=tuple(
                sorted(actions, key=lambda a: (str(a.incident_id), a.domain, str(a.request_id)))
            )
        )

    def source(self, incident_id: UUID, domain: GovernanceDomain, request_id: UUID):
        sources = read_governance_pending(self.service.store, lambda i: i == incident_id)
        for source in sources:
            request = source.request
            is_review = isinstance(request, HumanReviewRequest)
            if is_review != (domain == GovernanceDomain.INCIDENT_REVIEW):
                continue
            identity = request.review_request_id if is_review else request.request_id
            if identity == request_id:
                return source
        table = "review_requests" if domain == GovernanceDomain.INCIDENT_REVIEW else "requests"
        with self.service.store.database.transaction(write=False) as connection:
            exists = connection.execute(
                f"SELECT 1 FROM {table} WHERE id=? AND incident_id=?",
                (str(request_id), str(incident_id)),
            ).fetchone()
        if exists:
            raise Conflict("Governance request already transitioned")
        raise NotFound("Governance request not found for incident")

    def detail(self, incident_id, domain, request_id, principal, credential):
        source = self.source(incident_id, domain, request_id)
        self.authority().authenticate_context(
            credential=credential, context=context_for(source, principal)
        )
        return action_view(source, self.service.governance_confirmation_preview is not None)

    def prepare(self, incident_id, domain, request_id, principal, credential, body):
        source = self.source(incident_id, domain, request_id)
        if content_digest(source.request) != body.expected_request_digest:
            raise Conflict("Governance request digest changed")
        if source.incident.anchor != source.request.target.snapshot:
            raise Conflict("Governance request snapshot is stale")
        context = context_for(source, principal, body)
        trusted = self.authority().authenticate_context(credential=credential, context=context)
        if trusted != principal:
            raise HumanAuthorizationDenied("Authenticated request principal changed")
        callback = self.service.governance_confirmation_preview
        if callback is None:
            raise HumanAuthorizationDenied("Trusted non-consuming confirmation preview unavailable")
        try:
            confirmation = checked(HumanConfirmation, callback(credential, trusted, context))
        except (KeyError, ValueError, TypeError) as error:
            raise HumanAuthorizationDenied("Exact human confirmation unavailable") from error
        now = utc_now()
        if (
            confirmation.subject_id != trusted.subject_id
            or confirmation.provider_id != trusted.provider_id
            or confirmation.session_id != trusted.session_id
            or confirmation.action != context.action
            or confirmation.binding_digest != context.binding_digest
            or not trusted.authenticated_at <= confirmation.confirmed_at <= now
            or now - confirmation.confirmed_at > timedelta(minutes=5)
            or not now < confirmation.expires_at <= trusted.expires_at
        ):
            raise HumanAuthorizationDenied(
                "Confirmation identity/session/purpose/digest/expiry mismatch"
            )
        stored = SQLiteConfirmationConsumer(self.service.store.database).load(
            confirmation.provider_id, confirmation.confirmation_id
        )
        if stored and stored.consumed:
            raise Conflict("Confirmation already consumed")
        return source, GovernanceConfirmationView(
            action=action_view(source, True),
            context=context,
            decision=body.outcome.value
            if isinstance(body, ReviewDecisionInput)
            else "authorize_state_change",
            reason=body.reason if isinstance(body, ReviewDecisionInput) else None,
            confirmation_id=confirmation.confirmation_id,
            expires_at=confirmation.expires_at,
            subject_id=trusted.subject_id,
            session_id=trusted.session_id,
        )

    def submit_review(
        self, incident_id, request_id, principal, credential, body: SubmitReviewDecision
    ):
        source, preview = self.prepare(
            incident_id, GovernanceDomain.INCIDENT_REVIEW, request_id, principal, credential, body
        )
        self.match_confirmation(preview, body)
        record = self.service.reviews.record_review(
            source.request,
            reviewer_id=principal.subject_id,
            outcome=body.outcome,
            reason=body.reason,
            credential=credential,
        )
        return GovernanceResultView(
            domain=GovernanceDomain.INCIDENT_REVIEW,
            incident_id=incident_id,
            request_id=request_id,
            record_id=record.review_id,
            decision=record.outcome.value,
            recorded_at=record.recorded_at,
        )

    def submit_authorization(
        self, incident_id, request_id, principal, credential, body: SubmitStateAuthorization
    ):
        source, preview = self.prepare(
            incident_id,
            GovernanceDomain.STATE_AUTHORIZATION,
            request_id,
            principal,
            credential,
            body,
        )
        self.match_confirmation(preview, body)
        record = self.service.reviews.authorize_change(
            source.request, source.review, credential=credential
        )
        return GovernanceResultView(
            domain=GovernanceDomain.STATE_AUTHORIZATION,
            incident_id=incident_id,
            request_id=request_id,
            record_id=record.authorization_id,
            decision="state_change_authorization_issued",
            recorded_at=record.issued_at,
        )

    @staticmethod
    def match_confirmation(preview, body):
        if (
            preview.confirmation_id != body.confirmation_id
            or preview.context.binding_digest != body.expected_confirmation_digest
        ):
            raise HumanAuthorizationDenied("Submitted confirmation does not match exact preview")
