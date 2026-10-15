"""Existing persistent stores + explicit packet fixtures, including owned process SIGKILL."""

import asyncio
import json
import multiprocessing
import os
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest
from tests.unit.network_capture.test_packets import frame

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import (
    NetworkMonitor,
    configuration,
    configure,
)
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.realtime.queue import QueueFull
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    PacketCapture,
)
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from soc_agent.security_ai.operational.provenance import build_receipt, verify_receipt
from soc_agent.state.evidence import utc_now


def prepare(root):
    initialize(root, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3))
    configure(root, CaptureConfig(interface="lo", origin="EXPLICIT_PACKET_FIXTURE", idle_seconds=1))
    return root


def monitor(root):
    return NetworkMonitor(root, RuntimeStore(root))


def observation(pipeline, reverse=False):
    return parse_packet(
        frame(reverse=reverse),
        interface_id=pipeline.identity,
        timestamp=utc_now(),
        direction="INBOUND" if reverse else "OUTBOUND",
        native=False,
    )


def drain(pipeline):
    while pipeline.step() != "IDLE":
        pass


def source_count(pipeline):
    with pipeline.sources.database.transaction(write=False) as c:
        return c.execute("SELECT count(*) FROM operational_sources").fetchone()[0]


def test_packet_dns_source_receipt_and_flow_restart_idempotency(tmp_path):
    root = prepare(tmp_path / "runtime")
    m = monitor(root)
    p = m.pipeline
    packet = observation(p)
    assert p.packet(packet, "fixture-generation", 1)
    assert not p.packet(packet, "fixture-generation", 1)
    drain(p)
    p.flush(utc_now(), "SHUTDOWN")
    drain(p)
    assert source_count(p) == 2
    assert p.queue.counts() == {"DONE": 2}
    with p.queue.database.transaction(write=False) as c:
        rows = c.execute("SELECT * FROM realtime_events ORDER BY rowid").fetchall()
        assert "Private123" not in "".join(r["payload"] for r in rows)
        event = p.queue._decode(rows[0])
    dns = p.dns_event(event)
    assert dns is not None and dns.source_event_id == str(event.event_id)
    assert dns.question.query_name is None and dns.inference_status == "NOT_INFERABLE"
    assert dns.digest == p.dns_event(event).digest
    stored = p._source(event, p.decode(event))
    receipt = build_receipt(p.sources, incident_id=p.incident, sources=(stored,))
    assert verify_receipt(receipt, p.sources, incident_id=p.incident, sources=(stored,)) == receipt
    assert receipt.rule_status == "UNVERIFIED" and receipt.inference_status == "NOT_INFERABLE"
    new = monitor(root).pipeline
    new.recover()
    drain(new)
    assert source_count(new) == 2 and new.queue.counts() == {"DONE": 2}
    assert new.audit.verify_audit()


@pytest.mark.parametrize(
    "attack", ["interface", "origin", "incident", "digest", "flow_stats", "metadata"]
)
def test_source_or_flow_tampering_rejected(tmp_path, attack):
    m = monitor(prepare(tmp_path / "runtime"))
    p = m.pipeline
    packet = observation(p)
    if attack in ("interface", "origin"):
        changed = packet.model_copy(
            update={"interface_id": "b" * 64}
            if attack == "interface"
            else {"timestamp_origin": "KERNEL_SO_TIMESTAMPNS"}
        )
        with pytest.raises(ValueError):
            p.packet(changed, "fixture-generation", 1)
        return
    if attack == "metadata":
        event = p.event(packet, "fixture-generation", 1)
        forged = event.model_copy(
            update={"metadata": event.metadata.model_copy(update={"channel": "FORGED_CHANNEL"})}
        )
        with pytest.raises(ValueError, match="SOURCE_IDENTITY"):
            p.decode(forged)
        return
    p.packet(packet, "fixture-generation", 1)
    if attack == "digest":
        with p.queue.database.transaction() as c:
            c.execute("UPDATE realtime_events SET digest=?", ("f" * 64,))
        with pytest.raises(ValueError):
            p.step()
        assert source_count(p) == 0
    elif attack == "incident":
        claim = p.queue.claim()
        source = p._source(claim.event, p.decode(claim.event))
        with pytest.raises(ValueError, match="INCIDENT"):
            p.sources.ingest(
                source,
                expected_incident=uuid4(),
                expected_source_digest=source.content_digest,
                received_at=utc_now(),
            )
    else:
        drain(p)
        summary = p.table.expire(utc_now(), "SHUTDOWN")[0]
        forged = summary.model_copy(update={"forward_packets": 999})
        p.queue.enqueue(p.event(forged, "fixture-generation"))
        with pytest.raises(ValueError, match="STATISTICS"):
            p.step()
        assert source_count(p) == 1


class FixtureCapture:
    def __init__(self, identity, *, stats=(0, 0), denied=False):
        self.identity, self.stats, self.denied = identity, stats, denied
        self.frames = [(frame(), utc_now(), "OUTBOUND")]
        self.closed = False

    def open(self):
        if self.denied:
            raise CaptureUnavailable("PERMISSION_DENIED")

    def receive(self):
        return self.frames.pop(0) if self.frames else None

    def statistics(self):
        return self.stats

    def close(self):
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["none", "permission", "drops", "unknown"])
async def test_continuous_fixture_capture_health_and_zero_inference(tmp_path, failure):
    root = prepare(tmp_path / "runtime")
    m = monitor(root)
    capture = FixtureCapture(
        m.identity,
        stats=None if failure == "unknown" else (1, 2) if failure == "drops" else (1, 0),
        denied=failure == "permission",
    )
    m = NetworkMonitor(root, RuntimeStore(root), capture=capture)
    task = asyncio.create_task(m.run())
    await asyncio.sleep(0.25)
    m.stopped.set()
    await task
    assert capture.closed and m.metrics["inference_count"] == 0
    assert all(g["inference"] == "BLOCKED" for g in m.metrics["gates"].values())
    if failure == "none":
        assert m.metrics["state"] == "STOPPED" and m.metrics["dns_queries"] == 1
        assert source_count(m.pipeline) == 2
        assert m.metrics["packets_per_second"] >= 0
    else:
        assert m.metrics["state"] == "DEGRADED" and m.metrics["readiness"] == "NOT_READY"
        assert m.metrics["capture_drops"] == (2 if failure == "drops" else None)
    assert m.store.verify_audit()


def test_config_tamper_symlink_and_runtime_writer_lock(tmp_path):
    root = prepare(tmp_path / "runtime")
    with exclusive_runtime_lock(root / "writer.lock"):
        with pytest.raises(BlockingIOError):
            configure(root, CaptureConfig(interface="lo"))
    path = root / "network/config.json"
    payload = json.loads(path.read_text())
    payload["interface_id"] = "f" * 64
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="DIGEST"):
        configuration(root, RuntimeStore(root))
    path.unlink()
    path.symlink_to(tmp_path / "external")
    with pytest.raises(ValueError):
        configuration(root, RuntimeStore(root))


def child(root, point, connection):
    with exclusive_runtime_lock(Path(root) / "writer.lock"):
        m = monitor(Path(root))
        p = m.pipeline
        value = observation(p)
        event = p.event(value, "crash-fixture", 1)
        p.queue.enqueue(event, cursor_source="network:last_persisted")
        if point >= 2:
            claim = p.queue.claim()
        if point >= 3:
            source = p._source(event, value)
            p.sources.ingest(
                source,
                expected_incident=p.incident,
                expected_source_digest=source.content_digest,
                received_at=utc_now(),
            )
        if point >= 4:
            receipt = build_receipt(p.sources, incident_id=p.incident, sources=(source,))
            p.audit_once(str(event.event_id), receipt)
        if point >= 5:
            p.queue.finish(claim, {"inference": "NOT_INFERABLE", "workflow": "DIAGNOSTIC_ONLY"})
        connection.send((os.getpid(), point))
        connection.recv()  # Only this owned child is killed by the test parent.


@pytest.mark.parametrize("point", [1, 2, 3, 4, 5])
def test_owned_child_crash_recovers_source_and_audit_once(tmp_path, point):
    root = prepare(tmp_path / "runtime")
    context = multiprocessing.get_context("spawn")
    parent, remote = context.Pipe()
    process = context.Process(target=child, args=(str(root), point, remote))
    process.start()
    try:
        assert parent.poll(20), "owned child readiness timeout"
        pid, ready = parent.recv()
        assert pid == process.pid and ready == point and process.is_alive()
        process.kill()
        process.join(10)
        assert process.exitcode == -9
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)
        parent.close()
        remote.close()
    p = monitor(root).pipeline
    p.recover()
    drain(p)
    assert source_count(p) == 2 and p.queue.counts() == {"DONE": 2}
    assert p.audit.verify_audit()
    for db in (p.sources.database, p.queue.database, p.audit.database):
        with db.transaction(write=False) as c:
            assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with p.audit.database.transaction(write=False) as c:
        records = [json.loads(r[0]) for r in c.execute("SELECT payload FROM monitor_audit")]
    committed = [r for r in records if r["kind"] == "NETWORK_SOURCE_COMMITTED"]
    assert len(committed) == 2


def test_queue_backpressure_does_not_publish_checkpoint(tmp_path):
    p = monitor(prepare(tmp_path / "runtime")).pipeline
    value = observation(p)
    for i in range(p.queue.capacity):
        p.queue.enqueue(p.event(value, "backpressure", i))
    before = p.queue.cursor("network:last_persisted")
    with pytest.raises(QueueFull):
        p.packet(value, "backpressure", 999)
    assert p.queue.cursor("network:last_persisted") == before


def test_permission_diagnostic_does_not_elevate_or_run_commands(monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError()

    monkeypatch.setattr("socket.socket", denied)
    capture = PacketCapture(CaptureConfig(interface="lo"))
    with pytest.raises(CaptureUnavailable, match="PERMISSION_DENIED"):
        capture.open()
    assert capture.socket is None


def test_sqlite_write_failure_keeps_unacked_event(tmp_path, monkeypatch):
    p = monitor(prepare(tmp_path / "runtime")).pipeline
    p.packet(observation(p), "failure", 1)

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("sanitized fixture disk full")

    monkeypatch.setattr(p.sources, "ingest", fail)
    with pytest.raises(sqlite3.OperationalError):
        p.step()
    assert p.queue.counts() == {"CLAIMED": 1}
    monkeypatch.undo()
    new = monitor(p.audit.directory).pipeline
    new.recover()
    drain(new)
    assert new.queue.counts() == {"DONE": 2}
