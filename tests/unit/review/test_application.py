from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from tests.review_support import HumanConfirmations, authorize, record_review

from soc_agent.decision import IncidentDecisionEngine
from soc_agent.review import (
    ApplicationResult,
    AuthorizationAlreadyApplied,
    HumanReviewService,
    InMemoryIncidentStateStore,
    ReviewError,
    SeverityChange,
    StaleSnapshotError,
    StateTransitionDenied,
    StatusChange,
)
from soc_agent.review.identity import state_fingerprint
from soc_agent.state import Evidence, IncidentState, IncidentStatus
from soc_agent.state.evidence import utc_now


def test_normal_application_is_atomic_and_auditable(prepared):
    state, decision, _, store, service, review, request, authorization = prepared
    originals = tuple(
        v.model_dump_json() for v in (state, decision, review, request, authorization)
    )
    result = service.apply(state, decision, review, request, authorization)
    assert result.incident_state.severity == "high"
    assert result.incident_state.status == state.status
    assert result.incident_state.model_dump(exclude={"severity", "updated_at"}) == state.model_dump(
        exclude={"severity", "updated_at"}
    )
    assert result.incident_state.updated_at > state.updated_at
    assert (
        tuple(v.model_dump_json() for v in (state, decision, review, request, authorization))
        == originals
    )
    assert store.load(state.incident_id).state == result.incident_state
    assert store.applications() == (result,)
    audit = result.audit
    assert audit.target.incident_id == state.incident_id
    assert audit.target.decision_id == decision.decision_id
    assert audit.review_id == review.review_id
    assert audit.request_id == request.request_id
    assert audit.authorization_id == authorization.authorization_id
    assert audit.changes == request.changes
    assert audit.transition_version == "incident-state-transition:v1"
    assert audit.resulting_snapshot.revision == request.target.snapshot.revision + 1
    assert audit.resulting_snapshot.fingerprint == state_fingerprint(result.incident_state)
    assert audit.outcome == "applied"


@pytest.mark.parametrize("dual", [False, True])
def test_status_and_multifield_scope(case, dual):
    state, decision, authority, store, service = case
    review = record_review(service, authority, service.request_review(state, decision))
    changes = (StatusChange(before="new", after="triaging"),)
    if dual:
        changes += (SeverityChange(before="info", after="medium"),)
    request = service.propose_change(review, changes=changes, reason="Human selected fields")
    authorization = authorize(service, authority, request, review)
    result = service.apply(state, decision, review, request, authorization)
    assert result.incident_state.status == "triaging"
    assert result.incident_state.severity == ("medium" if dual else "info")
    assert result.incident_state.model_dump(
        exclude={"status", "severity", "updated_at"}
    ) == state.model_dump(exclude={"status", "severity", "updated_at"})


@pytest.mark.parametrize("before", list(IncidentStatus))
@pytest.mark.parametrize("after", list(IncidentStatus))
def test_explicit_transition_matrix(case, before, after):
    state, decision, authority, _, _ = case
    state = IncidentState.model_validate(state.model_dump() | {"status": before})
    store = InMemoryIncidentStateStore((state,))
    service = HumanReviewService(store=store, authority=authority)
    review = record_review(service, authority, service.request_review(state, decision))
    permitted = {
        ("new", "triaging"),
        ("triaging", "investigating"),
        ("investigating", "assessing"),
        ("assessing", "investigating"),
        ("assessing", "closed"),
    }
    if (before, after) not in permitted:
        with pytest.raises(ValueError):
            service.propose_change(
                review,
                changes=(StatusChange(before=before, after=after),),
                reason="Explicit transition test",
            )
        assert store.load(state.incident_id).state == state
        return
    request = service.propose_change(
        review,
        changes=(StatusChange(before=before, after=after),),
        reason="Explicit transition test",
    )
    authorization = authorize(service, authority, request, review)
    assert (
        service.apply(state, decision, review, request, authorization).incident_state.status
        == after
    )


def test_closed_severity_change_denied(case):
    state, decision, authority, _, _ = case
    state = IncidentState.model_validate(state.model_dump() | {"status": "closed"})
    store = InMemoryIncidentStateStore((state,))
    service = HumanReviewService(store=store, authority=authority)
    review = record_review(service, authority, service.request_review(state, decision))
    with pytest.raises(StateTransitionDenied):
        service.propose_change(
            review, changes=(SeverityChange(before="info", after="low"),), reason="Denied"
        )


def test_multifield_validation_failure_is_all_or_nothing(case):
    state, decision, authority, store, service = case
    review = record_review(service, authority, service.request_review(state, decision))
    with pytest.raises(StateTransitionDenied):
        service.propose_change(
            review,
            changes=(
                SeverityChange(before="info", after="high"),
                StatusChange(before="new", after="closed"),
            ),
            reason="No partial severity update",
        )
    assert store.load(state.incident_id).state == state
    assert store.applications() == service.authorizations() == ()


def test_evidence_added_after_authorization_invalidates_whole_snapshot(prepared):
    state, decision, _, store, service, review, request, authorization = prepared
    later = store.append_evidence(
        request.target.snapshot,
        Evidence(
            incident_id=state.incident_id,
            source="later log",
            summary="New evidence",
            raw_data="new",
            observed_at=utc_now(),
        ),
    )
    assert (later.state.status, later.state.severity) == (state.status, state.severity)
    for supplied in (state, later.state):
        with pytest.raises(StaleSnapshotError):
            service.apply(supplied, decision, review, request, authorization)
    assert store.load(state.incident_id) == later
    assert store.applications() == ()


def test_snapshot_changes_during_human_confirmation(case):
    state, decision, authority, store, service = case
    review = record_review(service, authority, service.request_review(state, decision))
    request = service.propose_change(
        review, changes=(SeverityChange(before="info", after="low"),), reason="Review"
    )
    original = authority.verify

    def verify(**kwargs):
        store.append_evidence(
            request.target.snapshot,
            Evidence(
                incident_id=state.incident_id,
                source="race",
                summary="Race",
                raw_data="{}",
                observed_at=utc_now(),
            ),
        )
        return original(**kwargs)

    authority.verify = verify
    with pytest.raises(StaleSnapshotError):
        authorize(service, authority, request, review)
    assert service.authorizations() == ()


def test_replay_rejected(prepared):
    state, decision, _, store, service, review, request, authorization = prepared
    result = service.apply(state, decision, review, request, authorization)
    with pytest.raises(AuthorizationAlreadyApplied):
        service.apply(state, decision, review, request, authorization)
    assert store.applications() == (result,)


@pytest.mark.parametrize("same_authorization", [False, True])
def test_two_concurrent_applications_only_one_commits(prepared, same_authorization):
    state, decision, _, store, service, review, request, authorization = prepared
    if same_authorization:
        other = service, review, request, authorization
    else:
        # Distinct service locks and authorizations; the shared store must arbitrate.
        authority2 = HumanConfirmations()
        service2 = HumanReviewService(store=store, authority=authority2)
        review2 = record_review(service2, authority2, service2.request_review(state, decision))
        request2 = service2.propose_change(
            review2,
            changes=(SeverityChange(before="info", after="critical"),),
            reason="Concurrent review",
        )
        other = service2, review2, request2, authorize(service2, authority2, request2, review2)
    barrier = Barrier(2)

    def apply(args):
        worker, r, req, auth = args
        barrier.wait(timeout=5)
        try:
            return worker.apply(state, decision, r, req, auth)
        except ReviewError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(apply, [(service, review, request, authorization), other]))
    assert sum(isinstance(r, ApplicationResult) for r in results) == 1
    expected_error = AuthorizationAlreadyApplied if same_authorization else StaleSnapshotError
    assert sum(isinstance(r, expected_error) for r in results) == 1
    assert len(store.applications()) == 1
    assert store.load(state.incident_id).anchor.revision == 1


def test_failure_after_build_does_not_consume_or_commit(prepared, monkeypatch):
    state, decision, _, store, service, review, request, authorization = prepared

    def fail(*args, **kwargs):
        raise RuntimeError("Injected failure after new snapshot build, before atomic commit")

    with monkeypatch.context() as guard:
        guard.setattr(ApplicationResult, "model_validate", fail)
        with pytest.raises(RuntimeError, match="before atomic commit"):
            service.apply(state, decision, review, request, authorization)
    assert store.load(state.incident_id).state == state
    assert store.applications() == ()
    result = service.apply(state, decision, review, request, authorization)
    assert store.applications() == (result,)


@pytest.mark.parametrize(
    "kind", ["incident", "decision", "review", "state_value", "decision_clock"]
)
def test_cannot_rebind_authorization(prepared, kind):
    state, decision, authority, store, service, review, request, authorization = prepared
    original_state = state
    if kind == "incident":
        state = IncidentState()
    elif kind == "decision":
        assessment = decision.assessment.model_copy(update={"summary": "Another assessment"})
        decision = IncidentDecisionEngine().decide(state, assessment)
    elif kind == "decision_clock":
        from datetime import timedelta

        # Phase 4-2 ID ignores creation clocks; review pins full decision bytes too.
        assessment = decision.assessment.model_copy(
            update={"created_at": decision.assessment.created_at + timedelta(seconds=1)}
        )
        other = IncidentDecisionEngine().decide(state, assessment)
        assert other.decision_id == decision.decision_id
        decision = other
    elif kind == "review":
        review = record_review(service, authority, service.request_review(state, decision))
    else:
        state = IncidentState.model_validate(state.model_dump() | {"severity": "low"})
    with pytest.raises(ReviewError):
        service.apply(state, decision, review, request, authorization)
    assert store.load(original_state.incident_id).state == original_state
    assert store.applications() == ()


def test_repository_revision_and_identity_are_bound(prepared):
    state, _, _, store, _, _, request, authorization = prepared
    recreated = InMemoryIncidentStateStore((state,))
    assert (
        recreated.load(state.incident_id).anchor.fingerprint == request.target.snapshot.fingerprint
    )
    with pytest.raises(StaleSnapshotError):
        recreated.compare_and_apply(
            request.target.snapshot,
            authorization.authorization_id,
            lambda current: pytest.fail("Wrong store must fail before building"),
        )
    bad_revision = request.target.snapshot.model_copy(update={"revision": 99})
    with pytest.raises(StaleSnapshotError):
        store.compare_and_apply(
            bad_revision, uuid4(), lambda current: pytest.fail("Stale revision")
        )


@pytest.mark.parametrize("field", ["evidence_content", "confidence", "updated_at"])
def test_snapshot_fingerprint_covers_more_than_status_severity(prepared, field):
    from datetime import timedelta

    state, decision, _, store, service, review, request, authorization = prepared
    payload = state.model_dump()
    if field == "evidence_content":
        payload["evidence"][0]["raw_data"] = "Changed content under same evidence ID"
    elif field == "confidence":
        payload["confidence"] = 0.7
    else:
        payload["updated_at"] = state.updated_at + timedelta(seconds=1)
    altered = IncidentState.model_validate(payload)
    assert (altered.status, altered.severity) == (state.status, state.severity)
    assert state_fingerprint(altered) != state_fingerprint(state)
    with pytest.raises(StaleSnapshotError):
        service.apply(altered, decision, review, request, authorization)
    assert store.load(state.incident_id).state == state
    assert store.applications() == ()
