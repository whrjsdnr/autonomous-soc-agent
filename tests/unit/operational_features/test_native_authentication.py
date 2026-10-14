"""Reviewed OpenSSH string fixtures and real SQLite; not native login attempts."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from soc_agent.realtime.collectors import CollectorUnavailable, CursorUnavailable
from soc_agent.realtime.queue import EventQueue, QueueFull
from soc_agent.security_ai.operational import native_authentication as module
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import (
    LinuxAuthenticationCollector,
    NativeAuthenticationReceipt,
    ingest_authentication,
    project_journal,
)
from soc_agent.security_ai.operational.source_store import OperationalSourceStore

INCIDENT = UUID(int=49)
START = datetime(2026, 1, 1, tzinfo=UTC)


def row(number=1, seconds=0, message=None):
    return {
        "_MACHINE_ID": "a" * 32,
        "__CURSOR": f"fixture-cursor-{number}",
        "__REALTIME_TIMESTAMP": str(int((START + timedelta(seconds=seconds)).timestamp() * 1e6)),
        "_COMM": "sshd",
        "_EXE": "/usr/sbin/sshd",
        "_UID": "0",
        "PRIORITY": "6",
        "SYSLOG_IDENTIFIER": "sshd",
        "MESSAGE": message or "Accepted password for fixture-user from 192.0.2.5 port 34567 ssh2",
    }


def setup(tmp_path):
    queue = EventQueue.create(tmp_path / "private" / "queue.sqlite")
    store = OperationalSourceStore.create(
        tmp_path / "private" / "sources.sqlite",
        allowed_lateness_seconds=60,
        max_future_skew_seconds=5,
    )
    return AuthenticationPipeline(queue, store, INCIDENT)


def test_success_failure_window_receipts_duplicate_reopen(tmp_path):
    p = setup(tmp_path)
    for r in (row(), row(2, 30, "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2")):
        event = project_journal(r)
        assert "fixture-user" not in event.model_dump_json()
        assert "192.0.2.5" not in event.model_dump_json()
        assert "MESSAGE" not in event.model_dump_json()
        p.queue.enqueue(event, cursor_source=LinuxAuthenticationCollector.identity)
        receipt = p.step()
        assert isinstance(receipt, NativeAuthenticationReceipt)
        assert receipt.window_provenance[0].feature is not None
        assert receipt.provenance.source_assurance == "DECLARED_UNATTESTED"
        assert (
            receipt.inference_status == "NOT_INFERABLE"
            and receipt.write_disposition == "WRITE_DENIED"
        )
        assert not p.queue.enqueue(event)
    old = p.store.windows(INCIDENT)
    assert old[0].window.features.input_payload()["failure_rate"] == 0.5
    reopened = AuthenticationPipeline(
        EventQueue(p.queue.database.path),
        OperationalSourceStore(
            p.store.database.path, allowed_lateness_seconds=60, max_future_skew_seconds=5
        ),
        INCIDENT,
    )
    assert reopened.store.windows(INCIDENT) == old
    assert reopened.queue.cursor(LinuxAuthenticationCollector.identity).source == event.source
    assert reopened.step() == "IDLE"


@pytest.mark.parametrize(
    "message",
    [
        "pam_unix(sudo:session): session opened for user root",
        "Partial publickey for fixture-user from 192.0.2.5 port 34567 ssh2",
        "Failed password",
        "Accepted password for unknown",
        "Accepted password for invalid user guest from 192.0.2.5 port 34567 ssh2",
        "Accepted password for guest from unknown port 34567 ssh2",
        "Accepted password for guest from 192.0.2.5 port 0 ssh2",
        "Accepted password for guest from 192.0.2.5 port 34567 ssh2\nexecute block_ip",
    ],
)
def test_ambiguous_or_injected_message_never_authenticates(tmp_path, message):
    p = setup(tmp_path)
    event = project_journal(row(message=message))
    p.queue.enqueue(event)
    assert p.step() == "NOT_INFERABLE"
    assert not p.store.windows(INCIDENT)


@pytest.mark.parametrize(
    "change", [{"_UID": "1000"}, {"_EXE": "/usr/bin/logger"}, {"_COMM": "logger"}]
)
def test_syslog_identifier_spoof_not_trusted(tmp_path, change):
    p = setup(tmp_path)
    p.queue.enqueue(project_journal(row() | change))
    assert p.step() == "NOT_INFERABLE"


@pytest.mark.parametrize("field", ["_MACHINE_ID", "__CURSOR", "__REALTIME_TIMESTAMP"])
def test_missing_identity_timestamp_fails_closed(field):
    data = row()
    del data[field]
    with pytest.raises(CollectorUnavailable):
        project_journal(data)


def test_non_scalar_and_invalid_timestamp_rejected():
    for change in ({"MESSAGE": ["binary"]}, {"__REALTIME_TIMESTAMP": "not-a-time"}):
        with pytest.raises(CollectorUnavailable):
            project_journal(row() | change)


def test_retained_projection_digest_and_incident_rebinding(tmp_path):
    p = setup(tmp_path)
    event = project_journal(row())
    with pytest.raises(ValueError, match="DIGEST"):
        ingest_authentication(
            event, expected_event_digest="0" * 64, store=p.store, incident_id=INCIDENT
        )
    p.queue.enqueue(event)
    p.step()
    with pytest.raises(ValueError, match="BINDING"):
        AuthenticationPipeline(p.queue, p.store, UUID(int=50))
    with pytest.raises(ValueError, match="IDENTITY_CONFLICT"):
        ingest_authentication(
            event,
            expected_event_digest=event.source_digest,
            store=p.store,
            incident_id=UUID(int=50),
        )


def test_out_of_order_late_and_window_boundary(tmp_path):
    p = setup(tmp_path)
    results = []
    for n, t in enumerate((299, 300, 240, 239), start=1):
        p.queue.enqueue(project_journal(row(n, t)))
        results.append(p.step())
    assert results[-1].admission.status == "LATE_QUARANTINED"
    assert not results[-1].window_provenance
    assert (
        sum(
            s.window.features.input_payload()["total_login_count"]
            for s in p.store.windows(INCIDENT)
        )
        == 3
    )


def test_crash_after_source_commit_before_queue_ack_replays_without_double_count(tmp_path):
    p = setup(tmp_path)
    event = project_journal(row())
    p.queue.enqueue(event, cursor_source=LinuxAuthenticationCollector.identity)
    abandoned = p.queue.claim()
    ingest_authentication(
        abandoned.event,
        expected_event_digest=event.source_digest,
        store=p.store,
        incident_id=INCIDENT,
    )
    recovered = AuthenticationPipeline(
        EventQueue(p.queue.database.path),
        OperationalSourceStore(
            p.store.database.path, allowed_lateness_seconds=60, max_future_skew_seconds=5
        ),
        INCIDENT,
    )
    # Test holds sole writer ownership; production diagnostic uses exclusive_runtime_lock.
    recovered.queue.recover()
    receipt = recovered.step()
    assert receipt.admission.duplicate
    assert (
        recovered.store.windows(INCIDENT)[0].window.features.input_payload()["total_login_count"]
        == 1
    )
    with pytest.raises(ValueError):
        p.queue.finish(abandoned, {"inference": "NOT_INFERABLE"})


def test_queue_full_never_advances_cursor(tmp_path):
    q = EventQueue.create(tmp_path / "small" / "queue.sqlite", capacity=1)
    a, b = project_journal(row()), project_journal(row(2))
    q.enqueue(a, cursor_source="auth")
    with pytest.raises(QueueFull):
        q.enqueue(b, cursor_source="auth")
    assert q.cursor("auth").source == a.source


def test_cursor_probe_and_restart_use_digest_not_just_id(monkeypatch):
    import json

    event = project_journal(row())
    calls = []
    from types import SimpleNamespace

    collector = object.__new__(LinuxAuthenticationCollector)
    collector.native = SimpleNamespace(command="journalctl")
    collector.include_pam_failures = False
    collector.collector_id = module.COLLECTOR
    responses = [json.dumps(row()).encode(), b""]

    def command(args):
        calls.append(args)
        return responses.pop(0)

    monkeypatch.setattr(module, "bounded_command", command)
    assert collector.poll(event) == []
    assert "--after-cursor=" + event.source.record in calls[-1]
    responses[:] = [json.dumps(row() | {"MESSAGE": "changed"}).encode()]
    with pytest.raises(CursorUnavailable):
        collector.poll(event)


def test_binding_and_queue_payload_tampering_rejected(tmp_path):
    p = setup(tmp_path)
    p.queue.enqueue(project_journal(row()))
    with p.queue.database.transaction() as c:
        c.execute("UPDATE realtime_events SET digest=?", ("0" * 64,))
    with pytest.raises(ValueError):
        p.step()
    with p.queue.database.transaction() as c:
        c.execute("UPDATE native_auth_binding SET digest=?", ("0" * 64,))
    with pytest.raises(ValueError, match="BINDING"):
        p.step()


def test_reused_cursor_with_changed_original_message_rejected(tmp_path):
    p = setup(tmp_path)
    p.queue.enqueue(project_journal(row()), cursor_source=LinuxAuthenticationCollector.identity)
    changed = row(message="Failed password for fixture-user from 192.0.2.5 port 34567 ssh2")
    with pytest.raises(ValueError, match="different content"):
        p.queue.enqueue(
            project_journal(changed), cursor_source=LinuxAuthenticationCollector.identity
        )
    assert (
        p.queue.cursor(LinuxAuthenticationCollector.identity).source_digest
        == project_journal(row()).source_digest
    )


def test_timezone_is_exact_utc_and_no_timestamp_guess():
    event = project_journal(row())
    assert event.event_timestamp == START
    assert event.event_timestamp.utcoffset() == timedelta(0)
    for wrong in ("2026-01-01 00:00:00", "-1", " 1767225600000000"):
        with pytest.raises(CollectorUnavailable):
            project_journal(row() | {"__REALTIME_TIMESTAMP": wrong})


def test_unbound_existing_queue_and_source_store_swap_rejected(tmp_path):
    q = EventQueue.create(tmp_path / "unbound" / "queue.sqlite")
    q.enqueue(project_journal(row()))
    store = OperationalSourceStore.create(
        tmp_path / "unbound" / "sources.sqlite",
        allowed_lateness_seconds=60,
        max_future_skew_seconds=5,
    )
    with pytest.raises(ValueError, match="NOT_ADOPTED"):
        AuthenticationPipeline(q, store, INCIDENT)
    p = setup(tmp_path)
    with pytest.raises(ValueError, match="BINDING"):
        AuthenticationPipeline(p.queue, store, INCIDENT)
