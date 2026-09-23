"""Explicit human review, issuance and application; no tool or model services."""

from datetime import timedelta
from threading import RLock
from uuid import UUID

from pydantic import ValidationError

from soc_agent.decision import IncidentDecision
from soc_agent.review.authority import (
    DenyHumanAuthority,
    HumanAction,
    HumanAuthority,
    VerifiedHumanAction,
)
from soc_agent.review.errors import HumanAuthorizationDenied, ReviewError, StaleSnapshotError
from soc_agent.review.identity import content_digest, state_fingerprint
from soc_agent.review.models import (
    ApplicationAudit,
    ApplicationFailure,
    ApplicationResult,
    HumanReviewRecord,
    HumanReviewRequest,
    ReviewIntent,
    ReviewOutcome,
    ReviewTarget,
    StateChange,
    StateChangeAuthorization,
    StateChangeRequest,
    StoredIncident,
)
from soc_agent.review.store import IncidentStateStore
from soc_agent.review.transitions import validate_changes
from soc_agent.review.validation import checked, validate_decision
from soc_agent.state import IncidentState
from soc_agent.state.evidence import utc_now


class HumanReviewService:
    """Trusted application boundary; issuance ledgers live only in this service instance.

    Never register this service, its authority, or its store as an LLM tool. Caller
    supplied subject strings are attribution only until verified by the authority.
    """

    def __init__(
        self, *, store: IncidentStateStore, authority: HumanAuthority | None = None
    ) -> None:
        self._store = store
        self._authority = authority if authority is not None else DenyHumanAuthority()
        self._lock = RLock()
        self._failures: tuple[ApplicationFailure, ...] = ()
        self._decisions: dict[str, IncidentDecision] = {}
        self._review_requests: dict[UUID, HumanReviewRequest] = {}
        self._reviews: dict[UUID, HumanReviewRecord] = {}
        self._requests: dict[UUID, StateChangeRequest] = {}
        self._authorizations: dict[UUID, StateChangeAuthorization] = {}

    def _current(
        self, target: ReviewTarget, current: StoredIncident | None = None
    ) -> StoredIncident:
        current = current if current is not None else self._store.load(target.incident_id)
        if current.anchor != target.snapshot:
            raise StaleSnapshotError("Review targets an outdated snapshot")
        return current

    def request_review(
        self, state: IncidentState, decision: IncidentDecision
    ) -> HumanReviewRequest:
        state = checked(IncidentState, state)
        decision = checked(IncidentDecision, decision)
        validate_decision(state, decision)
        with self._lock:
            current = self._store.load(state.incident_id)
            if current.anchor.fingerprint != state_fingerprint(state):
                raise StaleSnapshotError("Supplied state differs from authoritative state")
            digest = content_digest(decision)
            request = HumanReviewRequest(
                target=ReviewTarget(
                    incident_id=state.incident_id,
                    decision_id=decision.decision_id,
                    decision_digest=digest,
                    decision_version=decision.decision_version,
                    decision_rule_version=decision.rule_version,
                    snapshot=current.anchor,
                )
            )
            self._decisions[digest] = decision
            self._review_requests[request.review_request_id] = request
            return request

    def _review_request(self, request: HumanReviewRequest) -> HumanReviewRequest:
        request = checked(HumanReviewRequest, request)
        if self._review_requests.get(request.review_request_id) != request:
            raise ReviewError("Unknown or changed review request")
        if request.target.decision_digest not in self._decisions:
            raise ReviewError("Unknown decision")
        self._current(request.target)
        return request

    def _verify(self, credential: str, action: HumanAction, digest: str) -> VerifiedHumanAction:
        confirmation = checked(
            VerifiedHumanAction,
            self._authority.verify(credential=credential, action=action, binding_digest=digest),
        )
        if confirmation.action != action or confirmation.binding_digest != digest:
            raise HumanAuthorizationDenied("Human confirmation is not bound to this exact action")
        return confirmation

    def record_review(
        self,
        request: HumanReviewRequest,
        *,
        reviewer_id: str,
        outcome: ReviewOutcome,
        reason: str,
        credential: str,
    ) -> HumanReviewRecord:
        with self._lock:
            request = self._review_request(request)
        intent = ReviewIntent(
            review_request_id=request.review_request_id,
            target=request.target,
            reviewer_id=reviewer_id,
            outcome=outcome,
            reason=reason,
        )
        confirmation = self._verify(credential, HumanAction.RECORD_REVIEW, content_digest(intent))
        if confirmation.subject_id != intent.reviewer_id:
            raise HumanAuthorizationDenied("Reviewer differs from authenticated human")
        with self._lock:
            self._review_request(request)
            if any(
                r.review_request_id == request.review_request_id for r in self._reviews.values()
            ):
                raise ReviewError("Review request already has a final record")
            record = HumanReviewRecord(
                **intent.model_dump(), recorded_at=max(utc_now(), request.created_at)
            )
            self._reviews[record.review_id] = record
            return record

    def _review(
        self, review: HumanReviewRecord, current: StoredIncident | None = None
    ) -> HumanReviewRecord:
        review = checked(HumanReviewRecord, review)
        if self._reviews.get(review.review_id) != review:
            raise ReviewError("Unknown or changed human review")
        request = self._review_requests[review.review_request_id]
        if request.target != review.target:
            raise ReviewError("Review target mismatch")
        self._current(review.target, current)
        if review.outcome != ReviewOutcome.CHANGE_ELIGIBLE:
            raise HumanAuthorizationDenied("Review does not allow a state change proposal")
        return review

    def propose_change(
        self, review: HumanReviewRecord, *, changes: tuple[StateChange, ...], reason: str
    ) -> StateChangeRequest:
        with self._lock:
            review = self._review(review)
            request = StateChangeRequest(
                target=review.target, review_id=review.review_id, changes=changes, reason=reason
            )
            request = checked(StateChangeRequest, request)
            validate_changes(self._current(request.target).state, request)
            self._requests[request.request_id] = request
            return request

    def _request(
        self,
        request: StateChangeRequest,
        review: HumanReviewRecord,
        current: StoredIncident | None = None,
    ) -> StateChangeRequest:
        request = checked(StateChangeRequest, request)
        self._review(review, current)
        if self._requests.get(request.request_id) != request:
            raise ReviewError("Unknown or changed state change request")
        if request.review_id != review.review_id or request.target != review.target:
            raise ReviewError("State change review binding mismatch")
        validate_changes(self._current(request.target, current).state, request)
        return request

    def authorize_change(
        self, request: StateChangeRequest, review: HumanReviewRecord, *, credential: str
    ) -> StateChangeAuthorization:
        with self._lock:
            request = self._request(request, review)
        digest = content_digest(request)
        confirmation = self._verify(credential, HumanAction.AUTHORIZE_STATE_CHANGE, digest)
        with self._lock:
            self._request(request, review)
            if any(
                a.request.request_id == request.request_id for a in self._authorizations.values()
            ):
                raise ReviewError("Request already has an authorization")
            authorization = StateChangeAuthorization(
                request=request,
                request_digest=digest,
                authorized_by=confirmation.subject_id,
                issued_at=max(utc_now(), review.recorded_at),
            )
            self._authorizations[authorization.authorization_id] = authorization
            return authorization

    def apply(
        self,
        state: IncidentState,
        decision: IncidentDecision,
        review: HumanReviewRecord,
        request: StateChangeRequest,
        authorization: StateChangeAuthorization,
    ) -> ApplicationResult:
        try:
            return self._apply(state, decision, review, request, authorization)
        except Exception as error:
            # Audit then re-raise unchanged: never turn a failure into a normal result.
            # Retain registered context only; do not log credentials or invalid raw payloads.
            with self._lock:
                known = None
                if type(request) is StateChangeRequest and type(request.request_id) is UUID:
                    known = self._requests.get(request.request_id)
                authorization_id = None
                if (
                    type(authorization) is StateChangeAuthorization
                    and type(authorization.authorization_id) is UUID
                ):
                    authorization_id = authorization.authorization_id
                reason = "Application failed before commit; inspect application error separately"
                if isinstance(error, ValidationError):
                    reason = "Application input schema validation failed"
                elif isinstance(error, ReviewError):
                    reason = str(error)[:2000] or "Application rejected"
                failure = ApplicationFailure(
                    registered_request=known,
                    authorization_id=authorization_id,
                    error_type=type(error).__name__,
                    reason=reason,
                )
                self._failures = (*self._failures, failure)
            raise

    def failures(self) -> tuple[ApplicationFailure, ...]:
        with self._lock:
            return self._failures

    def _apply(
        self,
        state: IncidentState,
        decision: IncidentDecision,
        review: HumanReviewRecord,
        request: StateChangeRequest,
        authorization: StateChangeAuthorization,
    ) -> ApplicationResult:
        state = checked(IncidentState, state)
        decision = checked(IncidentDecision, decision)
        review = checked(HumanReviewRecord, review)
        request = checked(StateChangeRequest, request)
        authorization = checked(StateChangeAuthorization, authorization)
        with self._lock:
            # Issuance provenance is mandatory; a well-shaped object or digest is not authority.
            if self._authorizations.get(authorization.authorization_id) != authorization:
                raise HumanAuthorizationDenied("Authorization was not issued by this service")
            if authorization.request != request or authorization.request_digest != content_digest(
                request
            ):
                raise HumanAuthorizationDenied("Authorization does not match the exact request")
            if (
                content_digest(decision) != request.target.decision_digest
                or self._decisions.get(request.target.decision_digest) != decision
                or decision.incident_id != state.incident_id
                or decision.decision_id != request.target.decision_id
            ):
                raise ReviewError("Decision/incident binding mismatch")
            if state_fingerprint(state) != request.target.snapshot.fingerprint:
                raise StaleSnapshotError("Caller supplied another snapshot")

            def build(current: StoredIncident) -> ApplicationResult:
                self._request(request, review, current)
                if state != current.state:
                    raise StaleSnapshotError("Caller state differs from atomic current state")
                timestamp = max(
                    utc_now(), authorization.issued_at, state.updated_at + timedelta(microseconds=1)
                )
                payload = state.model_dump()
                for change in request.changes:
                    payload[change.field] = change.after
                payload["updated_at"] = timestamp
                updated = IncidentState.model_validate(payload)
                anchor = current.anchor.model_validate(
                    current.anchor.model_dump()
                    | {
                        "revision": current.anchor.revision + 1,
                        "fingerprint": state_fingerprint(updated),
                    }
                )
                audit = ApplicationAudit(
                    target=request.target,
                    review_id=review.review_id,
                    request_id=request.request_id,
                    authorization_id=authorization.authorization_id,
                    authorized_by=authorization.authorized_by,
                    changes=request.changes,
                    resulting_snapshot=anchor,
                    applied_at=timestamp,
                )
                return ApplicationResult(incident_state=updated, audit=audit)

            return self._store.compare_and_apply(
                request.target.snapshot, authorization.authorization_id, build
            )

    def reviews(self) -> tuple[HumanReviewRecord, ...]:
        with self._lock:
            return tuple(self._reviews.values())

    def authorizations(self) -> tuple[StateChangeAuthorization, ...]:
        with self._lock:
            return tuple(self._authorizations.values())
