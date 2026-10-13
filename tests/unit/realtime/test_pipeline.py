from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from soc_agent.realtime.collectors import (
    CollectorUnavailable,
    LinuxJournalCollector,
    WindowsEventCollector,
)
from soc_agent.realtime.models import CommonEvent, SourceIdentity, SourceMetadata, native_event
from soc_agent.realtime.queue import EventQueue, QueueFull, QueueIntegrityError


def event(record="1"):
    return native_event(
        "linux",
        "journald:v1",
        SourceIdentity(namespace="journal", generation="machine", record=record),
        SourceMetadata(channel="journal", provider="sshd"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )


def queue(tmp_path, **kwargs):
    return EventQueue.create(tmp_path / "private" / "queue.sqlite", **kwargs)


def test_contract_identity_and_receipt():
    first = event()
    second = first.model_copy(
        update={"ingestion_timestamp": first.ingestion_timestamp + timedelta(seconds=1)}
    )
    assert first.source_digest == second.source_digest
    assert CommonEvent.model_validate_json(first.model_dump_json()) == first
    with pytest.raises(ValueError):
        CommonEvent.model_validate(first.model_dump() | {"event_id": uuid4()})
    with pytest.raises(ValueError):
        CommonEvent.model_validate(first.model_dump() | {"model_prediction": "attack"})


def test_no_naive_time_or_os_features():
    with pytest.raises(ValueError):
        CommonEvent.model_validate(event().model_dump() | {"event_timestamp": datetime(2026, 1, 1)})
    with pytest.raises(ValueError):
        CommonEvent.model_validate(
            event().model_dump() | {"provenance": "explicit_precomputed_fixture"}
        )


def test_enqueue_dedup_cursor_backpressure(tmp_path):
    q = queue(tmp_path, capacity=1)
    first = event()
    assert q.enqueue(first, cursor_source="collector")
    assert not q.enqueue(event(), cursor_source="collector")
    with pytest.raises(QueueFull):
        q.enqueue(event("2"), cursor_source="collector")
    assert q.cursor("collector") == first
    conflict = first.model_copy(
        update={"metadata": SourceMetadata(channel="journal", provider="different")}
    )
    with pytest.raises(QueueIntegrityError):
        q.enqueue(conflict)
    claim = q.claim()
    q.finish(claim, {"inference": "NOT_INFERABLE"})
    assert q.enqueue(event("2"), cursor_source="collector")


def test_reopen_recover_retry_poison_stale_ack(tmp_path):
    q = queue(tmp_path, retry_limit=2)
    q.enqueue(event())
    abandoned = q.claim()
    q = EventQueue(q.database.path, retry_limit=2)
    q.recover()
    replacement = q.claim()
    assert replacement.attempts == 2
    with pytest.raises(QueueIntegrityError):
        q.finish(abandoned, {})
    q.fail(replacement)
    assert q.counts() == {"POISON": 1}
    assert q.claim() is None


def test_payload_and_cursor_corruption(tmp_path):
    q = queue(tmp_path)
    q.enqueue(event(), cursor_source="source")
    with q.database.transaction() as c:
        c.execute("UPDATE realtime_events SET digest=?", ("0" * 64,))
    with pytest.raises(QueueIntegrityError):
        q.claim()
    with pytest.raises(QueueIntegrityError):
        q.cursor("source")


def test_commit_rollback_does_not_publish_cursor(tmp_path, monkeypatch):
    q = queue(tmp_path)

    def fail(_):
        raise OSError("injected commit failure")

    monkeypatch.setattr(q.database, "_commit", fail)
    with pytest.raises(Exception, match="Commit failed"):
        q.enqueue(event(), cursor_source="source")
    q = EventQueue(q.database.path)
    assert q.counts() == {}
    assert q.cursor("source") is None


def test_journal_parser_drops_raw_sensitive_data():
    record = {
        "_MACHINE_ID": "machine",
        "__CURSOR": "cursor",
        "__REALTIME_TIMESTAMP": "1767225600000000",
        "MESSAGE": "credential secret",
        "SYSLOG_IDENTIFIER": "sshd",
        "PRIORITY": "5",
    }
    parsed = LinuxJournalCollector.parse(record)
    assert "secret" not in parsed.model_dump_json()
    assert parsed.event_timestamp == datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(CollectorUnavailable):
        LinuxJournalCollector.parse({})


def test_windows_parser_drops_payload():
    import json

    data = json.dumps(
        [
            {
                "record": "12",
                "channel": "System",
                "computer": "host",
                "provider": "provider",
                "code": "1",
                "time": "2026-01-01T00:00:00.0000001Z",
                "EventData": "credential secret",
            }
        ]
    ).encode("utf-8")
    events = WindowsEventCollector.parse(data, "System")
    assert events[0].source.record == "12"
    assert "secret" not in events[0].model_dump_json()
    assert events[0].metadata.original_timestamp.endswith("0000001Z")
    with pytest.raises(CollectorUnavailable):
        WindowsEventCollector.parse(data, "Security")


def test_cursor_redirect_corruption(tmp_path):
    q = queue(tmp_path)
    q.enqueue(event("1"), cursor_source="collector")
    q.enqueue(event("2"))
    with q.database.transaction() as c:
        c.execute("UPDATE realtime_cursors SET event_id=?", (str(event("2").event_id),))
    with pytest.raises(QueueIntegrityError, match="cursor integrity"):
        q.cursor("collector")


def test_platform_cursor_loss_fail_closed(monkeypatch):
    import soc_agent.realtime.collectors as collectors

    collector = object.__new__(LinuxJournalCollector)
    collector.command = "journalctl"
    monkeypatch.setattr(collectors, "bounded_command", lambda _: b"")
    with pytest.raises(collectors.CursorUnavailable):
        collector.poll(event())
    windows = object.__new__(WindowsEventCollector)
    windows.channel = "System"
    windows.command = "wevtutil.exe"
    monkeypatch.setattr(windows, "query", lambda *_: [])
    with pytest.raises(collectors.CursorUnavailable):
        windows.poll(event())


def test_private_storage_security_unchanged(tmp_path):
    from soc_agent.review.persistence.secure_storage import validate_database_files

    q = queue(tmp_path)
    validate_database_files(q.database.path)
    assert q.database.path.is_file()


def test_windows_command_injection_rejected_before_spawn():
    collector = object.__new__(WindowsEventCollector)
    collector.channel = "System"
    with pytest.raises(CollectorUnavailable, match="query"):
        collector.query("'; malicious-command; '", 1)
    with pytest.raises(CollectorUnavailable, match="limit"):
        collector.query("*", "1; malicious-command")
    collector.channel = "System'; malicious-command"
    with pytest.raises(CollectorUnavailable, match="channel"):
        collector.query("*", 1)
