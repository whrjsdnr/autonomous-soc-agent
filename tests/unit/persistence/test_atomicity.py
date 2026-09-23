import sqlite3

import pytest

from soc_agent.review.persistence import (
    CommitOutcomeUnknown,
    PersistentHumanReviewService,
    SQLiteGovernanceStore,
    StorageError,
    ledger,
)


def unchanged(store, state, auth):
    reopened = SQLiteGovernanceStore(store.database.path)
    assert reopened.load(state.incident_id).state == state
    assert reopened.load(state.incident_id).anchor.revision == 0
    assert not reopened.authorization_status(auth.authorization_id).consumed
    assert reopened.applications() == ()
    assert all(e.event_type != "application_succeeded" for e in reopened.events())


@pytest.mark.parametrize(
    "table,event",
    [
        ("incidents", "UPDATE"),
        ("authorizations", "UPDATE"),
        ("applications", "INSERT"),
        ("audit_events", "INSERT"),
    ],
)
def test_sql_failure_rolls_back_entire_apply(prepared, table, event):
    state, decision, _, store, service, review, request, auth = prepared
    condition = "WHEN NEW.event_type='application_succeeded'" if table == "audit_events" else ""
    with sqlite3.connect(store.database.path) as db:
        db.execute(
            f"CREATE TRIGGER failure BEFORE {event} ON {table} {condition} "
            "BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
    with pytest.raises(StorageError):
        service.apply(state, decision, review, request, auth)
    unchanged(store, state, auth)
    assert store.events()[-1].event_type == "application_failed"
    with sqlite3.connect(store.database.path) as db:
        db.execute("DROP TRIGGER failure")
    assert service.apply(state, decision, review, request, auth).incident_state.severity == "medium"


def test_serialization_failure_before_update(prepared, monkeypatch):
    from soc_agent.state import IncidentState

    state, decision, _, store, service, review, request, auth = prepared
    original = ledger.serialize

    def fail(value):
        if isinstance(value, IncidentState) and value.severity == "medium":
            raise TypeError("injected serialization error")
        return original(value)

    monkeypatch.setattr(ledger, "serialize", fail)
    with pytest.raises(TypeError, match="serialization"):
        service.apply(state, decision, review, request, auth)
    unchanged(store, state, auth)


def test_authorization_lookup_db_failure(prepared, monkeypatch):
    from soc_agent.review.persistence.session import GovernanceSession

    state, decision, _, store, service, review, request, auth = prepared
    original = GovernanceSession.restore_service

    def fail(self, authority=None):
        raise sqlite3.OperationalError("authorization lookup unavailable")

    monkeypatch.setattr(GovernanceSession, "restore_service", fail)
    with pytest.raises(StorageError):
        service.apply(state, decision, review, request, auth)
    monkeypatch.setattr(GovernanceSession, "restore_service", original)
    unchanged(store, state, auth)


@pytest.mark.parametrize("after_commit", [False, True])
def test_commit_failure_or_lost_commit_response(prepared, monkeypatch, after_commit):
    state, decision, _, store, service, review, request, auth = prepared
    real_commit = store.database._commit
    fired = False

    def fail_once(connection):
        nonlocal fired
        if fired:
            return real_commit(connection)
        fired = True
        if after_commit:
            real_commit(connection)
        raise sqlite3.OperationalError("injected commit response failure")

    monkeypatch.setattr(store.database, "_commit", fail_once)
    expected = CommitOutcomeUnknown if after_commit else StorageError
    with pytest.raises(expected):
        service.apply(state, decision, review, request, auth)
    if after_commit:
        status = SQLiteGovernanceStore(store.database.path).authorization_status(
            auth.authorization_id
        )
        assert status.consumed
        assert status.application.incident_state.severity == "medium"
        assert store.events()[-1].event_type == "application_outcome_unknown"
        assert sum(e.event_type == "application_succeeded" for e in store.events()) == 1
    else:
        unchanged(store, state, auth)


def test_successful_commit_is_queryable_without_response(prepared):
    state, decision, _, store, service, review, request, auth = prepared
    service.apply(state, decision, review, request, auth)
    # A transport failure after this return cannot undo the commit.
    reopened = SQLiteGovernanceStore(store.database.path)
    assert reopened.authorization_status(auth.authorization_id).consumed
    assert len(reopened.applications()) == 1
    assert PersistentHumanReviewService(store=reopened).authorizations() == (auth,)


@pytest.mark.parametrize("table", ["authorizations", "applications", "audit_events"])
def test_silently_ignored_write_is_not_success(prepared, table):
    from soc_agent.review.persistence import StoredDataError

    state, decision, _, store, service, review, request, auth = prepared
    event = "UPDATE" if table == "authorizations" else "INSERT"
    condition = "WHEN NEW.event_type='application_succeeded'" if table == "audit_events" else ""
    with sqlite3.connect(store.database.path) as db:
        db.execute(
            f"CREATE TRIGGER ignored BEFORE {event} ON {table} {condition} "
            "BEGIN SELECT RAISE(IGNORE); END"
        )
    with pytest.raises(StoredDataError):
        service.apply(state, decision, review, request, auth)
    unchanged(store, state, auth)
