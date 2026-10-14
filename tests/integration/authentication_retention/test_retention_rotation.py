"""Real SQLite, actual collector parsing with a command-boundary journal fixture."""

import asyncio
import json
import sqlite3
from unittest.mock import patch

import pytest
from tests.authentication_crash_harness import open_pipeline, security_check
from tests.unit.operational_features.test_native_authentication import row

from soc_agent.realtime.collectors import CollectorUnavailable
from soc_agent.realtime.queue import QueueFull
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.operational import native_authentication as native
from soc_agent.security_ai.operational.journal_health import collect_with_health
from soc_agent.security_ai.operational.retention import (
    MaintenanceLog,
    RetentionDenied,
    deny_cleanup,
    retention_plan,
    storage_metrics,
)


def configured(tmp_path):
    p = open_pipeline(
        tmp_path / "private", native.LinuxAuthenticationCollector.identity, create=True
    )
    log = MaintenanceLog.create(tmp_path / "private" / "maintenance.sqlite", p)
    collector = native.LinuxAuthenticationCollector.__new__(native.LinuxAuthenticationCollector)
    collector.include_pam_failures = False
    collector.collector_id = native.COLLECTOR
    from types import SimpleNamespace

    collector.native = SimpleNamespace(command="journalctl-fixture")
    return p, log, collector


def journal(records):
    def command(args):
        cursor = next((a.split("=", 1)[1] for a in args if a.startswith("--cursor=")), None)
        after = next((a.split("=", 1)[1] for a in args if a.startswith("--after-cursor=")), None)
        amount = int(next(a.split("+")[1] for a in args if a.startswith("--lines=+")))
        if cursor:
            selected = [r for r in records if r["__CURSOR"] == cursor]
            selected = selected or records[:1]  # journal may seek a neighbouring retained entry
        elif after:
            index = next(i for i, r in enumerate(records) if r["__CURSOR"] == after)
            selected = records[index + 1 :]
        else:
            selected = records
        return b"\n".join(json.dumps(r).encode() for r in selected[:amount])

    return command


def ingest(p):
    for _ in range(12):
        if p.step() == "IDLE":
            return
    pytest.fail("DRAIN_LIMIT")


def test_retention_no_delete_even_for_done_and_unsupported(tmp_path):
    p, audit, collector = configured(tmp_path)
    records = [row(), row(2, 30, message="session metadata only")]
    with patch.object(native, "bounded_command", journal(records)):
        assert collect_with_health(p, collector, audit=audit).status == "INITIAL_READ"
    ingest(p)
    before = storage_metrics(p)
    plan = retention_plan(p, audit=audit)
    assert plan.eligible_count == 0 and plan.protected_count == 5
    assert plan.reference_integrity == "VALIDATED_LOCAL"
    assert {i.kind for i in plan.items} == {"QUEUE", "CURSOR", "SOURCE", "WINDOW"}
    with pytest.raises(RetentionDenied):
        deny_cleanup(plan, audit=audit)
    assert storage_metrics(p) == before
    assert [r["operation"] for r in audit.entries()][-2:] == ["RETENTION_DRY_RUN", "CLEANUP_DENIED"]
    # Existing actual guard and orchestrator with local test incident (helper default differs).
    from soc_agent.security_ai.operational.authentication_investigation import (
        investigate_authentication,
    )

    assert asyncio.run(investigate_authentication(p)).plan.steps[0].status.value == "completed"
    assert asyncio.run(security_check(p))["write_spy_calls"] == 0


@pytest.mark.parametrize("state", ["PENDING", "CLAIMED", "POISON"])
def test_pending_retry_poison_protected(tmp_path, state):
    p, audit, _ = configured(tmp_path)
    event = native.project_journal(row())
    p.queue.enqueue(event, cursor_source=p.binding["collector"])
    if state != "PENDING":
        claim = p.queue.claim()
        if state == "POISON":
            for _ in range(p.queue.retry_limit - 1):
                p.queue.fail(claim)
                claim = p.queue.claim()
            p.queue.fail(claim)
    plan = retention_plan(p, audit=audit)
    assert plan.eligible_count == 0
    assert "INCOMPLETE_OR_POISON" in plan.items[0].reasons


def test_unknown_corrupt_source_fail_closed(tmp_path):
    p, audit, _ = configured(tmp_path)
    p.queue.enqueue(native.project_journal(row()), cursor_source=p.binding["collector"])
    ingest(p)
    with p.store.database.transaction() as c:
        c.execute("UPDATE operational_sources SET digest=?", ("0" * 64,))
    plan = retention_plan(p, audit=audit)
    assert plan.reference_integrity == "UNVERIFIABLE" and plan.eligible_count == 0
    with pytest.raises(RetentionDenied):
        deny_cleanup(plan, audit=audit)


@pytest.mark.parametrize("removed", [False, True])
def test_rotation_retained_cursor_or_vacuum_gap_no_reset(tmp_path, removed):
    p, audit, collector = configured(tmp_path)
    initial = [row()]
    with patch.object(native, "bounded_command", journal(initial)):
        collect_with_health(p, collector, audit=audit)
    ingest(p)
    cursor = p.queue.cursor(collector.identity)
    records = [row(2, 30)] if removed else [row(), row(2, 30)]
    with patch.object(native, "bounded_command", journal(records)):
        health = collect_with_health(p, collector, audit=audit)
    assert health.status == ("GAP_DETECTED" if removed else "RESUMED_EXACT")
    if removed:
        assert not health.continuation_allowed and health.gap_extent == "UNKNOWN"
        assert p.queue.cursor(collector.identity) == cursor
        assert p.queue.counts() == {"DONE": 1}
        assert MaintenanceLog(audit.database.path, p).entries()[-1]["status"] == "GAP_DETECTED"
    else:
        ingest(p)
        assert storage_metrics(p)["source_record_count"] == 2


@pytest.mark.parametrize(
    "error,status",
    [
        (CollectorUnavailable("PERMISSION_DENIED: source unreadable"), "PERMISSION_DENIED"),
        (CollectorUnavailable("read failure"), "SOURCE_UNAVAILABLE"),
    ],
)
def test_source_unavailable_or_denied_no_cursor_change(tmp_path, error, status):
    p, audit, collector = configured(tmp_path)
    with patch.object(native, "bounded_command", side_effect=error):
        health = collect_with_health(p, collector, audit=audit)
    assert health.status == status and not health.continuation_allowed
    assert p.queue.cursor(collector.identity) is None


def test_malformed_journal_and_deleted_cursor_no_fallback(tmp_path):
    p, audit, collector = configured(tmp_path)
    with patch.object(native, "bounded_command", journal([row()])):
        collect_with_health(p, collector, audit=audit)
    with patch.object(native, "bounded_command", return_value=b"broken json"):
        assert collect_with_health(p, collector, audit=audit).status == "SOURCE_UNAVAILABLE"
    with p.queue.database.transaction() as c:
        c.execute("DELETE FROM realtime_cursors")  # isolated tamper fixture only
    with patch.object(native, "bounded_command", side_effect=AssertionError("must not poll")):
        assert collect_with_health(p, collector, audit=audit).status == "CURSOR_INVALID"


def test_sqlite_full_at_queue_commit_rolls_back_event_and_cursor(tmp_path):
    p, audit, collector = configured(tmp_path)
    commit = p.queue.database._commit

    def fail_write(c):
        if c.execute("SELECT count(*) FROM realtime_events").fetchone()[0]:
            raise sqlite3.OperationalError("database or disk is full")
        commit(c)

    with (
        patch.object(native, "bounded_command", journal([row()])),
        patch.object(p.queue.database, "_commit", fail_write),
    ):
        health = collect_with_health(p, collector, audit=audit)
    assert health.status == "STORE_FAILURE"
    assert not p.queue.counts() and p.queue.cursor(collector.identity) is None


def test_source_commit_failure_recovery_preserves_claim_and_no_double_count(tmp_path):
    p, audit, _ = configured(tmp_path)
    p.queue.enqueue(native.project_journal(row()), cursor_source=p.binding["collector"])
    with patch.object(
        p.store.database, "_commit", side_effect=sqlite3.OperationalError("disk full")
    ):
        with pytest.raises(StorageError):
            p.step()
    assert p.queue.counts() == {"PENDING": 1}
    with p.queue.database.transaction(write=False) as c:
        outcome = json.loads(c.execute("SELECT outcome FROM realtime_events").fetchone()[0])
        assert outcome["failure_category"] == "STORAGE_FAILURE"
    with p.store.database.transaction(write=False) as c:
        assert not c.execute("SELECT * FROM operational_sources").fetchall()
    p.queue.recover()  # sole writer isolated fixture
    ingest(p)
    assert storage_metrics(p)["source_record_count"] == 1


def test_queue_backpressure_keeps_committed_cursor(tmp_path):
    p, audit, collector = configured(tmp_path)
    with patch.object(native, "bounded_command", journal([row()])):
        collect_with_health(p, collector, audit=audit)
    cursor = p.queue.cursor(collector.identity)
    with (
        patch.object(native, "bounded_command", journal([row(), row(2, 30)])),
        patch.object(p.queue, "enqueue", side_effect=QueueFull("bounded full")),
    ):
        assert collect_with_health(p, collector, audit=audit).status == "BACKPRESSURE"
    assert p.queue.cursor(collector.identity) == cursor


def test_busy_and_unreadable_queue_fail_closed(tmp_path):
    p, audit, collector = configured(tmp_path)
    p.queue.database.timeout = 0.01
    # Shared lock contention: no system storage is filled or changed.
    connection = sqlite3.connect(p.queue.database.path, isolation_level=None)
    connection.execute("BEGIN EXCLUSIVE")
    try:
        assert collect_with_health(p, collector, audit=audit).status == "STORE_FAILURE"
    finally:
        connection.rollback()
        connection.close()
    with patch.object(
        p.queue.database, "_connect", side_effect=sqlite3.OperationalError("read failure")
    ):
        assert collect_with_health(p, collector, audit=audit).status == "STORE_FAILURE"


def test_observer_commit_failure_does_not_report_healthy(tmp_path):
    p, audit, collector = configured(tmp_path)
    with (
        patch.object(audit.database, "_commit", side_effect=sqlite3.OperationalError("full")),
        patch.object(native, "bounded_command", side_effect=AssertionError("must not poll")),
    ):
        with pytest.raises(StorageError):
            collect_with_health(p, collector, audit=audit)
    assert not p.queue.counts()


def test_partial_backpressure_publishes_only_last_durable_event(tmp_path):
    from tests.authentication_crash_harness import INCIDENT, OPTIONS

    from soc_agent.realtime.queue import EventQueue
    from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
    from soc_agent.security_ai.operational.source_store import OperationalSourceStore

    _, _, collector = configured(tmp_path)
    root = tmp_path / "small"
    queue = EventQueue.create(root / "queue.sqlite", capacity=1)
    store = OperationalSourceStore.create(root / "sources.sqlite", **OPTIONS)
    p = AuthenticationPipeline(queue, store, INCIDENT)
    audit = MaintenanceLog.create(root / "maintenance.sqlite", p)
    with patch.object(native, "bounded_command", journal([row(), row(2, 30)])):
        health = collect_with_health(p, collector, audit=audit)
    assert health.status == "BACKPRESSURE" and health.accepted_count == 1
    assert p.queue.cursor(collector.identity).source.record == row()["__CURSOR"]
    assert storage_metrics(p)["queue_depth"] == 1
    p.step()
    with patch.object(native, "bounded_command", journal([row(), row(2, 30)])):
        assert collect_with_health(p, collector, audit=audit).status == "RESUMED_EXACT"
    p.step()
    assert storage_metrics(p)["source_record_count"] == 2


def test_duplicate_after_exact_probe_is_reported_as_replay(tmp_path):
    p, audit, collector = configured(tmp_path)
    data = json.dumps(row()).encode()
    with patch.object(native, "bounded_command", return_value=data):
        collect_with_health(p, collector, audit=audit)
    p.step()
    with patch.object(native, "bounded_command", return_value=data):
        health = collect_with_health(p, collector, audit=audit)
    assert health.status == "RESUMED_WITH_REPLAY" and health.accepted_count == 0
    assert p.step() == "IDLE" and storage_metrics(p)["source_record_count"] == 1


def test_observer_binding_and_chain_tampering_rejected(tmp_path):
    p, audit, _ = configured(tmp_path)
    retention_plan(p, audit=audit)
    from tests.authentication_crash_harness import open_pipeline

    other = open_pipeline(
        tmp_path / "other", native.LinuxAuthenticationCollector.identity, create=True
    )
    with pytest.raises(RetentionDenied):
        retention_plan(other, audit=audit)
    with audit.database.transaction() as c:
        c.execute("UPDATE auth_maintenance_events SET digest=?", ("0" * 64,))
    with pytest.raises(RetentionDenied):
        audit.entries()
    with pytest.raises(RetentionDenied):
        retention_plan(p, audit=audit)
