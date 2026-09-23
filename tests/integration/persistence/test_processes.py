"""Spawn independent interpreters; no shared connection or in-memory issuance ledger."""

import multiprocessing
import os
import sqlite3

import pytest

from soc_agent.decision import IncidentDecision
from soc_agent.review import SeverityChange
from soc_agent.review.models import HumanReviewRecord, StateChangeAuthorization, StateChangeRequest
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.state import IncidentState
from tests.review_support import authorize, record_review


def apply_worker(path, packet, barrier, output):
    models = (
        IncidentState,
        IncidentDecision,
        HumanReviewRecord,
        StateChangeRequest,
        StateChangeAuthorization,
    )
    values = [model.model_validate_json(raw) for model, raw in zip(models, packet, strict=True)]
    service = PersistentHumanReviewService(store=SQLiteGovernanceStore(path))
    if barrier is not None:
        barrier.wait(timeout=30)
    try:
        service.apply(*values)
        outcome = "success"
    except Exception as error:
        outcome = type(error).__name__
    output.put((os.getpid(), outcome))


def crash_worker(path):
    db = sqlite3.connect(path)
    db.execute("BEGIN IMMEDIATE")
    db.execute("UPDATE incidents SET revision=revision+1")
    os._exit(73)


def packet(state, decision, review, request, auth):
    return tuple(v.model_dump_json() for v in (state, decision, review, request, auth))


@pytest.mark.parametrize("different", [False, True])
def test_independent_process_cas(prepared, different):
    state, decision, authority, store, service, review, request, auth = prepared
    packets = [packet(state, decision, review, request, auth)]
    if different:
        second_review = record_review(service, authority, service.request_review(state, decision))
        second_request = service.propose_change(
            second_review,
            changes=(SeverityChange(before="info", after="high"),),
            reason="Second human",
        )
        second_auth = authorize(service, authority, second_request, second_review)
        packets.append(packet(state, decision, second_review, second_request, second_auth))
    else:
        packets.append(packets[0])
    ctx = multiprocessing.get_context("spawn")
    barrier, output = ctx.Barrier(2), ctx.Queue()
    children = [
        ctx.Process(target=apply_worker, args=(store.database.path, p, barrier, output))
        for p in packets
    ]
    for child in children:
        child.start()
    results = [output.get(timeout=60) for _ in children]
    for child in children:
        child.join(timeout=30)
        assert child.exitcode == 0
    assert len({pid for pid, _ in results}) == 2
    assert sorted(outcome for _, outcome in results) == sorted(
        ["success", "StaleSnapshotError" if different else "AuthorizationAlreadyApplied"]
    )
    reopened = SQLiteGovernanceStore(store.database.path)
    assert reopened.load(state.incident_id).anchor.revision == 1
    assert len(reopened.applications()) == 1
    assert sum(e.event_type == "application_succeeded" for e in reopened.events()) == 1
    assert (
        sum(
            reopened.authorization_status(a.authorization_id).consumed
            for a in service.authorizations()
        )
        == 1
    )


def test_restart_in_new_interpreter_and_replay(prepared):
    state, decision, _, store, _, review, request, auth = prepared
    ctx = multiprocessing.get_context("spawn")
    for expected in ("success", "AuthorizationAlreadyApplied"):
        output = ctx.Queue()
        child = ctx.Process(
            target=apply_worker,
            args=(
                store.database.path,
                packet(state, decision, review, request, auth),
                None,
                output,
            ),
        )
        child.start()
        assert output.get(timeout=60)[1] == expected
        child.join(timeout=30)
        assert child.exitcode == 0
    reopened = SQLiteGovernanceStore(store.database.path)
    service = PersistentHumanReviewService(store=reopened)
    assert service.reviews() == (review,)
    assert service.requests() == (request,)
    assert service.authorizations() == (auth,)
    assert reopened.authorization_status(auth.authorization_id).consumed
    assert reopened.load(state.incident_id).anchor.revision == 1


def test_process_crash_rolls_back_uncommitted_state(prepared):
    state, _, _, store, _, _, _, auth = prepared
    child = multiprocessing.get_context("spawn").Process(
        target=crash_worker, args=(store.database.path,)
    )
    child.start()
    child.join(timeout=30)
    assert child.exitcode == 73
    reopened = SQLiteGovernanceStore(store.database.path)
    assert reopened.load(state.incident_id).state == state
    assert reopened.load(state.incident_id).anchor.revision == 0
    assert not reopened.authorization_status(auth.authorization_id).consumed
    assert reopened.applications() == ()
