"""Synthetic IPC/persistence and actual research binaries; never native capture."""

import asyncio
import json
import sqlite3
import threading
import time
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.live_network_performance import fixture_packets, messages
from tests.live_transport_diagnostics import fixture_channel
from tests.unit.live_network.test_parity import wire

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.research import live_service
from soc_agent.security_ai.research.live_service import LiveMonitoring, LiveResearch, bound_request
from soc_agent.security_ai.research.models import digest
from soc_agent.state.evidence import utc_now


def monitor_for(root, capture, generation, *, fixture=False, handler=None):
    initialize(root, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3))
    configure(
        root,
        CaptureConfig(
            interface="lo", origin="EXPLICIT_PACKET_FIXTURE" if fixture else "NATIVE_AF_PACKET"
        ),
    )
    monitor = NetworkMonitor(
        root, RuntimeStore(root), capture=capture, generation=str(generation), flow_handler=handler
    )
    capture.stop = monitor.stopped
    return monitor


def feed(capture, sender, session, count):
    # Old event times reproduce the actual delayed-processing false idle timeout.
    packets = fixture_packets(count, session.interface_id, utc_now() - timedelta(seconds=45))
    _, records = messages(session, packets)
    records[-1] = records[-1].model_copy(
        update={"received_frames": count * 2, "sent_packets": count, "elapsed_seconds": 1.0}
    )
    errors = []

    def produce():
        try:
            for record in records:
                sender.sendall(record.model_dump_json(exclude_none=True).encode())
        except OSError as error:
            errors.append(type(error).__name__)

    thread = threading.Thread(target=produce)
    thread.start()
    return thread, errors


@pytest.mark.asyncio
async def test_frame_limit_clean_closed_drains_all_256_and_never_invents_idle_flow(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "observer", separated=True)
    thread, errors = feed(capture, sender, session, 256)
    try:
        monitor = monitor_for(tmp_path / "runtime", capture, session.session_id)
        await asyncio.wait_for(monitor.run(), 90)
        assert monitor.metrics["finalization"] == "VERIFIED", monitor.metrics
        assert monitor.metrics["packets_collected"] == capture.delivered == 256
        assert capture.completion_verified() and capture.packets.empty()
        assert not (capture.directory / "transport-unprocessed.json").exists()
        assert monitor.pipeline.queue.counts() == {"DONE": 258}
        with monitor.pipeline.queue.database.transaction(write=False) as c:
            rows = c.execute(
                "SELECT * FROM realtime_events WHERE json_extract(payload,'$.metadata.code')='flow'"
            ).fetchall()
        assert [
            monitor.pipeline.decode(monitor.pipeline.queue._decode(r)).close_reason for r in rows
        ]
        assert all(
            monitor.pipeline.decode(monitor.pipeline.queue._decode(r)).close_reason
            == "PACKET_LIMIT"
            for r in rows
        )
        assert monitor.store.verify_audit() and monitor.metrics["inference_count"] == 0
        assert not errors and not capture.reader_thread.is_alive()
    finally:
        capture.close()
        sender.close()
        thread.join(1)
    assert not thread.is_alive()


@pytest.mark.asyncio
async def test_persistence_failure_accounts_for_buffer_and_does_not_finalize(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "observer", separated=True)
    thread, _ = feed(capture, sender, session, 32)
    monitor = monitor_for(tmp_path / "runtime", capture, session.session_id)
    original = monitor.pipeline.packet

    def fail(packet, generation, sequence):
        if sequence == 3:
            try:
                raise sqlite3.OperationalError("fixture failure")
            except sqlite3.Error as error:
                raise StorageError("fixture persistence failure") from error
        return original(packet, generation, sequence)

    monitor.pipeline.packet = fail
    try:
        await asyncio.wait_for(monitor.run(), 5)
        assert monitor.metrics["finalization"] == "BLOCKED"
        assert monitor.metrics["state"] == "DEGRADED"
        assert monitor.pipeline.queue.counts() == {"PENDING": 2}
        assert capture.delivered == 3  # dequeue is not a persistence receipt
        receipt = json.loads((capture.directory / "transport-unprocessed.json").read_text())
        assert receipt["reason"] == "PERSISTENCE_OR_FINALIZATION_FAILED"
        assert receipt["queued_packets"] == 29
        assert monitor.metrics["inference_count"] == 0
    finally:
        capture.close()
        sender.close()
        thread.join(1)


@pytest.mark.asyncio
async def test_explicit_stop_does_not_drain_or_authorize_pending_metadata(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "observer", separated=True)
    thread, _ = feed(capture, sender, session, 8)
    thread.join(1)
    for _ in range(100):
        if capture.terminal is not None:
            break
        await asyncio.sleep(0.005)
    monitor = monitor_for(tmp_path / "runtime", capture, session.session_id)
    capture.close()  # Explicit cancellation is distinct from clean CLOSED draining.
    monitor.stopped.set()
    try:
        await monitor.run()
        assert monitor.metrics["finalization"] == "NOT_APPROVED_STOP_OR_MISSING_COUNTERS"
        assert capture.packets.qsize() == 8 and capture.delivered == 0
        assert monitor.pipeline.queue.counts() == {}
    finally:
        capture.close()
        sender.close()


@pytest.mark.asyncio
async def test_corrupt_audit_cannot_finalize_after_clean_closed(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "observer", separated=True)
    thread, _ = feed(capture, sender, session, 8)
    monitor = monitor_for(tmp_path / "runtime", capture, session.session_id)
    with monitor.store.database.transaction() as c:
        c.execute("UPDATE monitor_audit SET digest=? WHERE sequence=1", ("0" * 64,))
    try:
        await monitor.run()
        assert monitor.metrics["finalization"] == "BLOCKED"
        assert monitor.metrics["last_error"] == "NETWORK_SHUTDOWN_INCOMPLETE"
        with pytest.raises(ValueError, match="AUDIT_INTEGRITY"):
            monitor.store.verify_audit()
    finally:
        capture.close()
        sender.close()
        thread.join(1)


class CompletedFixture:
    """In-memory packets with explicit FIXTURE origin, not a helper attestation."""

    def __init__(self, identity):
        self.identity = identity
        self.closed = threading.Event()
        self.delivered = 0
        self.last = None
        self.sampled = False
        self.values = [
            (wire(length=length, flags=flags), utc_now() - timedelta(seconds=seconds), "OUTBOUND")
            for length, flags, seconds in [(40, 2, 33), (60, 16, 32.5), (80, 1, 32), (40, 2, 1)]
        ]

    def open(self):
        pass

    def receive(self):
        if self.delivered == len(self.values):
            self.stop.set()
            return None
        value = self.values[self.delivered]
        self.delivered += 1
        self.last = value[1]
        return value

    def statistics(self):
        result = (0 if self.sampled else 4, 0)
        self.sampled = True
        return result

    def flow_watermark(self, now):
        return self.last or now

    def completion_verified(self):
        return self.delivered == 4

    def close(self, **kwargs):
        self.closed.set()


@pytest.mark.asyncio
async def test_finalized_fixture_actual_quality_edge_receipts_and_recovery(tmp_path):
    from soc_agent.security_ai.operational.network_capture.capture import interface_identity

    session = uuid4()
    service = LiveMonitoring(tmp_path)
    capture = CompletedFixture(interface_identity("lo"))
    monitor = monitor_for(
        tmp_path / "runtime", capture, session, fixture=True, handler=service.on_flow
    )
    service.monitor = monitor
    service.session = SimpleNamespace(session_id=session)
    service.demo = LiveResearch(tmp_path / "demo")
    await service.demo.start()
    try:
        await monitor.run()
        assert monitor.metrics["finalization"] == "VERIFIED"
        assert service.demo.snapshot()["records"] == []
        assert service.pending.qsize() == 1  # Only the first naturally expired flow.
        service.collection_done.set()
        await service._consume()
        records = service.demo.snapshot()["records"]
        assert len(records) == 2
        assert {r["receipt"]["profile"] for r in records} == {"quality", "edge"}
        assert all(r["receipt"]["origin"] == "FIXTURE" for r in records)
        assert all(r["receipt"]["status"] == "RESEARCH_ONLY" for r in records)
        assert all(r["investigation"]["status"] == "ASSESSED_READ_ONLY" for r in records)
        assert all(r["investigation"]["checkpoint_restored"] for r in records)
        assert service.pending.empty() and monitor.store.verify_audit()
        await service.demo.stop()
        restored = LiveResearch(tmp_path / "demo")
        await restored.start()
        with monitor.pipeline.queue.database.transaction(write=False) as c:
            rows = c.execute(
                "SELECT * FROM realtime_events WHERE json_extract(payload,'$.metadata.code')='flow'"
            ).fetchall()
        event = monitor.pipeline.queue._decode(rows[0])
        flow = monitor.pipeline.decode(event)
        for profile in ("quality", "edge"):
            request = bound_request(monitor, session, event, flow, profile)
            key = digest({"session": str(session), "flow": flow.flow_id, "profile": profile})
            assert (await restored.dispatch(request, key))["status"] == "CACHED_NO_NEW_INFERENCE"
        assert len(restored.snapshot()["records"]) == 2
        await restored.stop()
    finally:
        await service.demo.stop()


@pytest.mark.parametrize("legacy_outer_read", [True, False])
def test_source_validation_releases_outer_read_before_nested_reads(
    tmp_path, monkeypatch, legacy_outer_read
):
    from contextlib import nullcontext

    from tests.integration.live_network.test_research import persisted

    monitor, session, event, flow = persisted(tmp_path / "runtime")
    monitor.metrics["finalization"] = "VERIFIED"
    request = bound_request(monitor, session, event, flow, "quality")
    service = LiveMonitoring(tmp_path)
    service.monitor, service.session = monitor, SimpleNamespace(session_id=session)
    service.capture = SimpleNamespace(
        ready=True,
        counter_issue=None,
        reader_failed=lambda: False,
        closed=threading.Event(),
        completion_verified=lambda: True,
    )
    database = monitor.pipeline.queue.database
    database.timeout = 0.05
    errors = []
    original = live_service.bound_request

    def concurrent_writer():
        try:
            with database.transaction() as c:
                c.execute("CREATE TABLE isolated_lock_fixture(value INTEGER)")
        except StorageError as error:
            errors.append(getattr(error.__cause__, "sqlite_errorname", "UNKNOWN"))

    def validate_outside_read(*args):
        thread = threading.Thread(target=concurrent_writer)
        thread.start()
        thread.join(1)
        assert not thread.is_alive()
        return original(*args)

    monkeypatch.setattr(live_service, "bound_request", validate_outside_read)
    context = database.transaction(write=False) if legacy_outer_read else nullcontext()
    with context as c:
        if c is not None:
            c.execute("SELECT * FROM realtime_events LIMIT 1").fetchone()
        service.validate_native_source(request)
    assert errors == (["SQLITE_BUSY"] if legacy_outer_read else [])


@pytest.mark.asyncio
async def test_service_dispatches_only_after_clean_closed_persistence_and_audit(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "observer")
    runtime = capture.directory / "runtime"
    initialize(
        runtime, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3)
    )
    configure(runtime, CaptureConfig(interface="lo"))
    packets = fixture_packets(4, session.interface_id, utc_now() - timedelta(seconds=40))
    packets[-1] = packets[-1].model_copy(
        update={
            "timestamp": packets[-1].timestamp + timedelta(seconds=31),
            "capture_timestamp_ns": packets[-1].capture_timestamp_ns + 31_000_000_000,
        }
    )
    _, records = messages(session, packets)
    records[-1] = records[-1].model_copy(
        update={"received_frames": 8, "sent_packets": 4, "elapsed_seconds": 31.0}
    )
    service = LiveMonitoring(tmp_path)
    service.capture, service.session, service.directory = capture, session, capture.directory
    # Attestation is substituted. Deliver the Mock READY at handshake, not before
    # potentially slow SQLite setup, which must not consume its 2s heartbeat lease.
    capture.handshake = lambda: setattr(capture, "last_heartbeat", time.monotonic())
    dispatched = []

    class MockModel:
        async def dispatch(self, request, key):
            assert service.monitor.metrics["finalization"] == "VERIFIED"
            assert capture.completion_verified() and capture.closed.is_set()
            assert service.monitor.pipeline.queue.counts() == {"DONE": 6}
            assert service.monitor.store.verify_audit()
            dispatched.append(request.profile)
            return {"status": "COMPLETE"}

        async def stop(self):
            pass

    service.demo = MockModel()
    errors = []

    def produce():
        try:
            for record in records:
                sender.sendall(record.model_dump_json(exclude_none=True).encode())
        except OSError as error:
            errors.append(type(error).__name__)

    thread = threading.Thread(target=produce)
    thread.start()
    try:
        await asyncio.wait_for(service._run(), 10)
        assert service.state == "STOPPED", service.last_error
        assert dispatched == ["quality", "edge"] and not errors
        assert not capture.reader_thread.is_alive()
    finally:
        capture.close()
        sender.close()
        thread.join(1)
