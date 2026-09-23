"""Persistent composition of the unchanged Phase 4-3 human-governance service."""

from collections.abc import Callable
from uuid import UUID

from soc_agent.decision import IncidentDecision
from soc_agent.review.authority import HumanAuthority
from soc_agent.review.models import (
    ApplicationResult,
    HumanReviewRecord,
    HumanReviewRequest,
    ReviewOutcome,
    StateChange,
    StateChangeAuthorization,
    StateChangeRequest,
)
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import (
    CommitOutcomeUnknown,
    EventType,
    FailureAuditUnavailable,
    GovernanceEvent,
)
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.review.persistence.store import SQLiteGovernanceStore
from soc_agent.review.service import HumanReviewService
from soc_agent.review.validation import checked
from soc_agent.state import IncidentState

Context = HumanReviewRequest | HumanReviewRecord | StateChangeRequest | None


def event_for(
    kind: EventType,
    context: Context = None,
    *,
    actor: str | None = None,
    authorization_id: UUID | None = None,
    failure_type: str | None = None,
) -> GovernanceEvent:
    if not isinstance(context, (HumanReviewRequest, HumanReviewRecord, StateChangeRequest)):
        context = None
    if context is not None:
        try:
            context = checked(type(context), context)
        except (ValueError, TypeError, AttributeError):
            context = None
    target = context.target if context is not None else None
    review_id = (
        context.review_id if isinstance(context, (HumanReviewRecord, StateChangeRequest)) else None
    )
    request_id = context.request_id if isinstance(context, StateChangeRequest) else None
    return GovernanceEvent(
        event_type=kind,
        incident_id=target.incident_id if target else None,
        decision_id=target.decision_id if target else None,
        review_id=review_id,
        request_id=request_id,
        authorization_id=authorization_id,
        actor_id=actor,
        before=target.snapshot if target else None,
        changes=context.changes if isinstance(context, StateChangeRequest) else (),
        rule_version=context.transition_version
        if isinstance(context, StateChangeRequest)
        else None,
        failure_type=failure_type,
    )


class PersistentHumanReviewService:
    """Explicit SQLite-only construction; no implicit selection of a volatile backend.

    Trusted human confirmation runs within the write transaction. Providers must
    bound their latency; no prompt/UI/network interaction is implemented here.
    """

    def __init__(
        self, *, store: SQLiteGovernanceStore, authority: HumanAuthority | None = None
    ) -> None:
        if not isinstance(store, SQLiteGovernanceStore):
            raise TypeError("Persistent service requires an explicit SQLiteGovernanceStore")
        self.store = store
        self.authority = authority

    def _run[T](
        self,
        operation: Callable[[HumanReviewService, GovernanceSession], T],
        *,
        failure_kind: EventType | None = None,
        context: Context = None,
        authorization_id: UUID | None = None,
    ) -> T:
        try:
            with self.store.database.transaction() as connection:
                session = GovernanceSession(connection, self.store.store_id)
                service = session.restore_service(self.authority)
                return operation(service, session)
        except CommitOutcomeUnknown as error:
            if failure_kind:
                try:
                    self._failure(
                        "application_outcome_unknown"
                        if failure_kind == "application_failed"
                        else "transaction_outcome_unknown",
                        context,
                        authorization_id,
                        error,
                    )
                except FailureAuditUnavailable:
                    error.add_note(
                        "Uncertain outcome audit could not be persisted; reconcile first"
                    )
            raise
        except Exception as error:
            if failure_kind:
                self._failure(failure_kind, context, authorization_id, error)
            raise

    def _failure(
        self, kind: EventType, context: Context, authorization_id: UUID | None, error: Exception
    ) -> None:
        event = event_for(
            kind, context, authorization_id=authorization_id, failure_type=type(error).__name__
        )
        try:
            with self.store.database.transaction() as connection:
                ledger.append_event(connection, event)
        except Exception as audit_error:
            failure = FailureAuditUnavailable(
                "Operation failed and separate failure audit is unavailable"
            )
            failure.add_note(f"Audit failure category: {type(audit_error).__name__}")
            raise failure from error

    def request_review(
        self, state: IncidentState, decision: IncidentDecision
    ) -> HumanReviewRequest:
        def operation(service, session):
            result = service.request_review(state, decision)
            ledger.insert(session.connection, checked(IncidentDecision, decision))
            ledger.insert(session.connection, result)
            ledger.append_event(session.connection, event_for("review_requested", result))
            return result

        return self._run(operation)

    def record_review(
        self,
        request: HumanReviewRequest,
        *,
        reviewer_id: str,
        outcome: ReviewOutcome,
        reason: str,
        credential: str,
    ) -> HumanReviewRecord:
        def operation(service, session):
            result = service.record_review(
                request,
                reviewer_id=reviewer_id,
                outcome=outcome,
                reason=reason,
                credential=credential,
            )
            ledger.insert(session.connection, result)
            ledger.append_event(
                session.connection, event_for("review_recorded", result, actor=result.reviewer_id)
            )
            return result

        return self._run(operation, failure_kind="review_rejected", context=request)

    def propose_change(
        self, review: HumanReviewRecord, *, changes: tuple[StateChange, ...], reason: str
    ) -> StateChangeRequest:
        def operation(service, session):
            result = service.propose_change(review, changes=changes, reason=reason)
            ledger.insert(session.connection, result)
            ledger.append_event(session.connection, event_for("change_requested", result))
            return result

        return self._run(operation)

    def authorize_change(
        self, request: StateChangeRequest, review: HumanReviewRecord, *, credential: str
    ) -> StateChangeAuthorization:
        def operation(service, session):
            result = service.authorize_change(request, review, credential=credential)
            ledger.insert(session.connection, result)
            ledger.append_event(
                session.connection,
                event_for(
                    "authorization_issued",
                    request,
                    actor=result.authorized_by,
                    authorization_id=result.authorization_id,
                ),
            )
            return result

        return self._run(operation, failure_kind="authorization_rejected", context=request)

    def apply(
        self,
        state: IncidentState,
        decision: IncidentDecision,
        review: HumanReviewRecord,
        request: StateChangeRequest,
        authorization: StateChangeAuthorization,
    ) -> ApplicationResult:
        identity = getattr(authorization, "authorization_id", None)
        identity = identity if isinstance(identity, UUID) else None
        return self._run(
            lambda service, session: service.apply(state, decision, review, request, authorization),
            failure_kind="application_failed",
            context=request,
            authorization_id=identity,
        )

    def _read(self, table: str):
        with self.store.database.transaction(write=False) as connection:
            GovernanceSession(connection, self.store.store_id).restore_service()
            return ledger.all_records(connection, table)

    def review_requests(self) -> tuple[HumanReviewRequest, ...]:
        return self._read("review_requests")

    def reviews(self) -> tuple[HumanReviewRecord, ...]:
        return self._read("reviews")

    def requests(self) -> tuple[StateChangeRequest, ...]:
        return self._read("requests")

    def authorizations(self) -> tuple[StateChangeAuthorization, ...]:
        return self._read("authorizations")

    def decisions(self) -> tuple[IncidentDecision, ...]:
        return self._read("decisions")
