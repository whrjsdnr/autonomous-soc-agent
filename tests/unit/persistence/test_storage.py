import sqlite3
from uuid import uuid4

import pytest

from soc_agent.review import (
    AuthorizationAlreadyApplied,
    HumanAuthorizationDenied,
    StaleSnapshotError,
)
from soc_agent.review.identity import state_fingerprint
from soc_agent.review.persistence import (
    PersistentHumanReviewService,
    SQLiteGovernanceStore,
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from soc_agent.state import Evidence
from soc_agent.state.evidence import utc_now


def test_registration_and_reopen(case):
    state, decision, authority, store, service = case
    loaded = store.load(state.incident_id)
    assert loaded.state == state
    assert loaded.anchor.revision == 0
    assert loaded.anchor.fingerprint == state_fingerprint(state)
    reopened = SQLiteGovernanceStore(store.database.path)
    assert reopened.store_id == store.store_id
    assert reopened.load(state.incident_id) == loaded
    with pytest.raises(StorageError):
        store.register(state)
    assert len(store.events()) == 1
    assert store.events()[0].event_type == "incident_registered"


def test_application_and_persistent_replay(prepared):
    state, decision, _, store, service, review, request, auth = prepared
    before = state.model_dump_json()
    result = service.apply(state, decision, review, request, auth)
    assert result.incident_state.severity == "medium"
    assert state.model_dump_json() == before
    reopened = SQLiteGovernanceStore(store.database.path)
    recovered = PersistentHumanReviewService(store=reopened)
    assert recovered.reviews() == (review,)
    assert recovered.requests() == (request,)
    assert recovered.authorizations() == (auth,)
    assert recovered.decisions() == (decision,)
    assert reopened.load(state.incident_id).anchor.revision == 1
    assert reopened.authorization_status(auth.authorization_id).application == result
    assert reopened.applications() == (result,)
    with pytest.raises(AuthorizationAlreadyApplied):
        recovered.apply(state, decision, review, request, auth)
    assert sum(e.event_type == "application_succeeded" for e in reopened.events()) == 1
    assert reopened.events()[-1].event_type == "application_failed"


def test_unused_auth_survives_restart(prepared):
    state, decision, _, store, _, review, request, auth = prepared
    reopened = SQLiteGovernanceStore(store.database.path)
    assert not reopened.authorization_status(auth.authorization_id).consumed
    result = PersistentHumanReviewService(store=reopened).apply(
        state, decision, review, request, auth
    )
    assert result.incident_state.severity == "medium"


def test_stale_after_evidence(prepared):
    state, decision, _, store, service, review, request, auth = prepared
    later = store.append_evidence(
        request.target.snapshot,
        Evidence(
            incident_id=state.incident_id,
            source="later",
            summary="More evidence",
            raw_data="{}",
            observed_at=utc_now(),
        ),
    )
    reopened = SQLiteGovernanceStore(store.database.path)
    with pytest.raises(StaleSnapshotError):
        PersistentHumanReviewService(store=reopened).apply(state, decision, review, request, auth)
    assert reopened.load(state.incident_id) == later
    assert not reopened.authorization_status(auth.authorization_id).consumed


@pytest.mark.parametrize("field", ["authorization_id", "authorized_by", "request_digest"])
def test_forged_authorization(prepared, field):
    state, decision, _, store, service, review, request, auth = prepared
    value = (
        uuid4()
        if field == "authorization_id"
        else ("mallory" if field == "authorized_by" else "0" * 64)
    )
    with pytest.raises(HumanAuthorizationDenied):
        service.apply(state, decision, review, request, auth.model_copy(update={field: value}))
    assert store.load(state.incident_id).state == state
    assert not store.authorization_status(auth.authorization_id).consumed


def test_default_boundary_denies_issuance(prepared):
    state, decision, _, store, service, review, request, auth = prepared
    denying = PersistentHumanReviewService(store=SQLiteGovernanceStore(store.database.path))
    with pytest.raises(HumanAuthorizationDenied):
        denying.authorize_change(request, review, credential="admin")
    assert store.events()[-1].event_type == "authorization_rejected"


@pytest.mark.parametrize("corruption", ["json", "fingerprint", "enum", "missing_field"])
def test_corrupt_state_rejected(case, corruption):
    import json

    state, _, _, store, _ = case
    with sqlite3.connect(store.database.path) as db:
        if corruption == "fingerprint":
            db.execute("UPDATE incidents SET fingerprint=?", ("0" * 64,))
        else:
            payload = state.model_dump(mode="json")
            if corruption == "enum":
                payload["status"] = "open"
            if corruption == "missing_field":
                del payload["incident_id"]
            db.execute(
                "UPDATE incidents SET payload=?",
                ("broken" if corruption == "json" else json.dumps(payload),),
            )
    with pytest.raises(StoredDataError):
        store.load(state.incident_id)


def test_unsupported_version_does_not_reset(case):
    state, _, _, store, _ = case
    with sqlite3.connect(store.database.path) as db:
        db.execute("PRAGMA user_version=99")
    with pytest.raises(UnsupportedSchemaError):
        SQLiteGovernanceStore(store.database.path)
    with sqlite3.connect(store.database.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 99
        assert db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1


def test_creation_and_path_permissions(case, tmp_path):
    *_, store, service = case
    with pytest.raises(FileExistsError):
        SQLiteGovernanceStore.create(store.database.path)
    with pytest.raises(ValueError):
        SQLiteGovernanceStore.create("relative.sqlite")
    assert store.database.path.stat().st_mode & 0o777 == 0o600
    link = tmp_path / "link.sqlite"
    link.symlink_to(store.database.path)
    with pytest.raises(ValueError):
        SQLiteGovernanceStore(link)
    store.database.path.chmod(0o644)
    with pytest.raises(ValueError):
        SQLiteGovernanceStore(store.database.path)


@pytest.mark.parametrize(
    "field,value", [("revision", 7), ("fingerprint", "0" * 64), ("repository_id", uuid4())]
)
def test_cas_anchor_mismatch(prepared, field, value):
    state, _, _, store, _, _, request, auth = prepared
    anchor = request.target.snapshot.model_copy(update={field: value})
    with pytest.raises(StaleSnapshotError):
        store.compare_and_apply(anchor, auth.authorization_id, lambda current: pytest.fail("build"))
    assert store.load(state.incident_id).state == state
    assert not store.authorization_status(auth.authorization_id).consumed


@pytest.mark.parametrize("part", ["decision", "review", "request", "incident"])
def test_cross_binding_rejected(prepared, part):
    from pydantic import ValidationError

    from soc_agent.review import ReviewError

    state, decision, _, store, service, review, request, auth = prepared
    original = state
    if part == "decision":
        decision = decision.model_copy(update={"decision_id": "0" * 64})
    elif part == "review":
        review = review.model_copy(update={"review_id": uuid4()})
    elif part == "request":
        request = request.model_copy(update={"request_id": uuid4()})
    else:
        state = state.model_copy(update={"incident_id": uuid4()})
    with pytest.raises((ReviewError, ValidationError)):
        service.apply(state, decision, review, request, auth)
    assert store.load(original.incident_id).state == original
    assert not store.authorization_status(auth.authorization_id).consumed


def test_transition_policy_rejected_before_issuance(prepared):
    from soc_agent.review import ReviewError, StatusChange

    state, _, _, store, service, review, _, _ = prepared
    with pytest.raises(ReviewError):
        service.propose_change(
            review, changes=(StatusChange(before="new", after="closed"),), reason="Invalid shortcut"
        )
    assert store.load(state.incident_id).state == state


def test_corrupt_authorization_ledger_rejected(prepared):
    state, decision, _, store, service, review, request, auth = prepared
    with sqlite3.connect(store.database.path) as db:
        db.execute("UPDATE authorizations SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        service.apply(state, decision, review, request, auth)
    assert store.load(state.incident_id).state == state
    assert store.events()[-1].event_type == "application_failed"
