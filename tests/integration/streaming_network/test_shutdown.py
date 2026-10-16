"""Ordinary-user Unix metadata fixtures; peer attestation is explicitly mocked.

No AF_PACKET, privilege command, native model authorization or traffic generation.
"""

import asyncio
import json
import socket
import threading
import time

import pytest
from tests.research_adapter_support import research_paths
from tests.unit.streaming_network.test_transport import native_shaped, stat

from soc_agent.security_ai.operational.network_capture import helper_transport
from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


async def connected(tmp_path, monkeypatch, *, policy=None):
    monkeypatch.setattr(helper_transport, "validate_peer", lambda *a, **kw: None)
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    assert (await owner.start(policy=policy))["listener_ready"]
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.settimeout(1)
    client.connect(owner.session.socket_address)
    client.sendall(stat(owner.session, 1, 0, kind="READY").model_dump_json().encode())
    for _ in range(200):
        if owner.state == "LIVE_COLLECTION":
            return owner, client
        await asyncio.sleep(0.01)
    client.close()
    await owner.stop(abort=True)
    raise AssertionError("fixture handshake failed")


def send_packet(owner, client, sequence, *, packet=None):
    session = owner.session
    client.sendall(stat(session, sequence + 1, sequence).model_dump_json().encode())
    client.sendall(
        StreamMessage(
            kind="PACKET",
            session_id=session.session_id,
            sequence=sequence,
            counter_sequence=sequence + 1,
            packet=packet or native_shaped(session, sequence),
        )
        .model_dump_json()
        .encode()
    )


def send_closed(owner, client, count, *, elapsed=1):
    client.sendall(
        StreamMessage(
            kind="CLOSED",
            session_id=owner.session.session_id,
            counter_sequence=count + 2,
            kernel_packets=0,
            kernel_packets_total=count,
            capture_drops=0,
            capture_drops_total=0,
            counter_status="COUNTER_VERIFIED",
            received_frames=count,
            sent_packets=count,
            elapsed_seconds=elapsed,
        )
        .model_dump_json()
        .encode()
    )


@pytest.mark.asyncio
async def test_automatic_event_time_abort_persists_error_and_causal_transport_reason(
    tmp_path, monkeypatch
):
    owner, client = await connected(tmp_path, monkeypatch)
    try:
        send_packet(owner, client, 1)
        send_packet(owner, client, 2, packet=native_shaped(owner.session, 0))
        for n in range(3, 7):
            send_packet(owner, client, n)
        await asyncio.wait_for(owner.task, 5)
        assert owner.last_error == "STREAM_TIME_REVERSED"
        state = owner.store.runtime.state()["network"]
        assert state["finalization"] == "BLOCKED"
        assert state["last_error"] == "STREAM_TIME_REVERSED"
        assert state["active_flows"] == state["retained_metadata_bytes"] == 0
        assert owner.capture.shutdown_reason == "CONTROLLER_ABORT:STREAM_TIME_REVERSED"
        assert not owner.capture.completion_verified()
        assert not list(owner.demo.directory.glob("receipt-*.json"))
        assert owner.store.queue.counts() == {}
        # Legacy storage could retain an older RUNNING sample after this audit.
        owner.store.runtime.update(network={"finalization": "RUNNING", "active_flows": 4})
        restored = StreamingMonitoring(tmp_path, paths=research_paths())
        snapshot = await restored.restore_latest()
        assert snapshot["last_error"] == "STREAM_TIME_REVERSED"
        assert snapshot["network"]["finalization"] == "BLOCKED"
        assert snapshot["network"]["inference_count"] == 0
    finally:
        client.close()
        await owner.stop(abort=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("completion", ["deadline", "frame_limit"])
async def test_automatic_closed_drains_without_gui_stop(tmp_path, monkeypatch, completion):
    policy = StreamPolicy(seconds=1, frames_per_second=1, burst_frames=1)
    owner, client = await connected(tmp_path, monkeypatch, policy=policy)
    count = 1 if completion == "deadline" else policy.frame_budget
    try:
        for n in range(1, count + 1):
            send_packet(owner, client, n)
        send_closed(owner, client, count)
        client.close()  # Helper's normal exit races reader drain.
        await asyncio.wait_for(owner.task, 5)
        assert not owner.stop_requested
        assert owner.state == "STOPPED", owner.last_error
        assert owner.capture.completion_verified()
        assert owner.metrics["packets_collected"] == count
        assert owner.metrics["finalization"] == "VERIFIED"
        assert (owner.directory / "verified-closed.json").is_file()
        assert not (owner.directory / "transport-unprocessed.json").exists()
        assert owner.store.runtime.verify_audit()
        assert not list(owner.demo.directory.glob("receipt-*.json"))  # Short shutdown flows.
    finally:
        client.close()
        await owner.stop()


@pytest.mark.asyncio
async def test_stop_sends_control_before_slow_persistence_returns(tmp_path, monkeypatch):
    owner, client = await connected(tmp_path, monkeypatch)
    entered, release = asyncio.Event(), asyncio.Event()
    original = owner.observe

    async def delayed(*args):
        entered.set()
        await release.wait()
        await original(*args)

    monkeypatch.setattr(owner, "observe", delayed)
    stopping = None
    try:
        send_packet(owner, client, 1)
        await entered.wait()
        stopping = asyncio.create_task(owner.stop())
        control = await asyncio.to_thread(client.recv, 64)
        assert control == b"STOP"
        send_closed(owner, client, 1)
        release.set()
        await asyncio.wait_for(stopping, 5)
        assert owner.capture.completion_verified()
        assert owner.metrics["packets_collected"] == 1
        assert owner.metrics["finalization"] == "VERIFIED"
        assert not (owner.directory / "transport-unprocessed.json").exists()
        closed = json.loads((owner.directory / "verified-closed.json").read_text())
        assert closed["sent_packets"] == 1
    finally:
        release.set()
        client.close()
        if stopping:
            await asyncio.gather(stopping, return_exceptions=True)
        await owner.stop(abort=True)


@pytest.mark.asyncio
async def test_closed_arrives_after_empty_receive_before_controller_checks_terminal(
    tmp_path, monkeypatch
):
    owner, client = await connected(tmp_path, monkeypatch)
    empty, release = threading.Event(), threading.Event()
    original = owner.capture.receive

    def race():
        value = original()
        if value is None and not empty.is_set():
            empty.set()
            assert release.wait(3)
        return value

    monkeypatch.setattr(owner.capture, "receive", race)
    try:
        assert await asyncio.to_thread(empty.wait, 2)
        send_packet(owner, client, 1)
        send_packet(owner, client, 2)
        send_closed(owner, client, 2)
        for _ in range(200):
            if owner.capture.terminal is not None:
                break
            await asyncio.sleep(0.005)
        assert owner.capture.packets.qsize() == 2
        release.set()
        await asyncio.wait_for(owner.task, 5)
        assert owner.state == "STOPPED", owner.last_error
        assert owner.metrics["packets_collected"] == 2
        assert owner.capture.completion_verified()
    finally:
        release.set()
        client.close()
        await owner.stop(abort=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "parent_disconnect",
        "reader_timeout",
        "unknown",
        "drop",
        "closed_write",
        "sqlite",
        "duplicate",
    ],
)
async def test_failed_completion_never_promotes_or_infers(tmp_path, monkeypatch, fault):
    owner, client = await connected(tmp_path, monkeypatch)
    try:
        if fault == "closed_write":
            original = helper_transport.write_private

            def fail(path, value):
                if path.name == "verified-closed.json":
                    raise OSError("FIXTURE_WRITE_FAILED")
                return original(path, value)

            monkeypatch.setattr(helper_transport, "write_private", fail)
            send_closed(owner, client, 0)
        elif fault == "sqlite":
            original = owner.store.runtime.update
            failed = False

            def fail_once(**fields):
                nonlocal failed
                if not failed:
                    failed = True
                    raise OSError("FIXTURE_SQLITE_COMMIT_FAILED")
                return original(**fields)

            monkeypatch.setattr(owner.store.runtime, "update", fail_once)
            send_packet(owner, client, 1)
        elif fault in ("unknown", "drop"):
            value = stat(
                owner.session,
                2,
                1,
                kind="CLOSED",
                received_frames=0,
                sent_packets=0,
                elapsed_seconds=1,
            )
            client.sendall(
                value.model_copy(
                    update={
                        "counter_status": "COUNTER_UNAVAILABLE"
                        if fault == "unknown"
                        else "CAPTURE_DROPS_DETECTED",
                        "capture_drops": None if fault == "unknown" else 1,
                        "capture_drops_total": None if fault == "unknown" else 1,
                    }
                )
                .model_dump_json()
                .encode()
            )
        elif fault == "duplicate":
            send_packet(owner, client, 1)
            client.sendall(
                StreamMessage(
                    kind="PACKET",
                    session_id=owner.session.session_id,
                    sequence=1,
                    counter_sequence=2,
                    packet=native_shaped(owner.session, 1),
                )
                .model_dump_json()
                .encode()
            )
        elif fault == "parent_disconnect":
            client.close()
        # reader_timeout deliberately sends no heartbeat/CLOSED; never capture.
        await asyncio.wait_for(owner.task, 6)
        assert owner.state == "ERROR", owner.snapshot()
        assert owner.metrics["finalization"] == "BLOCKED"
        assert not owner.capture.completion_verified()
        assert not list(owner.demo.directory.glob("receipt-*.json"))
        assert owner.store.queue.counts() == {}
        assert owner.store.runtime.verify_audit()
        if fault == "closed_write":
            assert owner.capture.terminal is None
            assert not (owner.directory / "verified-closed.json").exists()
    finally:
        client.close()
        await owner.stop(abort=True)


@pytest.mark.asyncio
async def test_duplicate_stop_and_backend_close_wait_for_closed_and_drain(tmp_path, monkeypatch):
    from soc_agent.gui.backend import Backend, GUIConfig

    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
    owner, client = await connected(tmp_path / "session", monkeypatch)
    backend = Backend(GUIConfig(data_directory=tmp_path / "backend"))
    backend.streaming_monitoring = owner
    entered, release = asyncio.Event(), asyncio.Event()
    original = owner.observe

    async def delayed(*args):
        entered.set()
        await release.wait()
        await original(*args)

    monkeypatch.setattr(owner, "observe", delayed)
    tasks = []
    try:
        send_packet(owner, client, 1)
        await entered.wait()
        tasks.append(asyncio.create_task(owner.stop()))
        assert await asyncio.to_thread(client.recv, 64) == b"STOP"
        tasks.append(asyncio.create_task(backend.close()))
        tasks.append(asyncio.create_task(owner.stop()))
        send_closed(owner, client, 1)
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks), 6)
        assert backend.closed
        assert owner.state == "STOPPED", owner.last_error
        assert owner.capture.completion_verified()
        assert not owner.capture.reader_thread.is_alive()
        assert owner.metrics["finalization"] == "VERIFIED"
        with owner.store.runtime.database.transaction(write=False) as connection:
            codes = [
                json.loads(row[0])["kind"]
                for row in connection.execute("SELECT payload FROM monitor_audit")
            ]
        assert codes.count("STREAM_STOP_DRAIN_REQUESTED") == 1
        assert "STREAM_ABORTED" not in codes
    finally:
        release.set()
        client.close()
        await asyncio.gather(*tasks, return_exceptions=True)
        await backend.close()


@pytest.mark.asyncio
async def test_control_send_failure_stays_blocked(tmp_path, monkeypatch):
    from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable

    owner, client = await connected(tmp_path, monkeypatch)

    def fail():
        raise CaptureUnavailable("STREAM_STOP_DISCONNECTED")

    monkeypatch.setattr(owner.capture, "request_stop", fail)
    try:
        await asyncio.wait_for(owner.stop(), 5)
        assert owner.state == "ERROR"
        assert owner.metrics["finalization"] == "BLOCKED"
        assert owner.last_error == "STREAM_STOP_DISCONNECTED"
        assert not owner.capture.completion_verified()
    finally:
        client.close()
        await owner.stop(abort=True)


@pytest.mark.asyncio
async def test_fresh_heartbeats_without_closed_hit_bounded_stop_deadline(tmp_path, monkeypatch):
    owner, client = await connected(tmp_path, monkeypatch, policy=StreamPolicy(graceful_seconds=1))

    async def heartbeats():
        sequence = 2
        while not owner.capture.closed.is_set():
            value = StreamMessage(
                kind="HEARTBEAT",
                session_id=owner.session.session_id,
                counter_sequence=sequence,
                kernel_packets=0,
                kernel_packets_total=0,
                capture_drops=0,
                capture_drops_total=0,
                counter_status="COUNTER_VERIFIED",
                received_frames=0,
                sent_packets=0,
            )
            try:
                client.sendall(value.model_dump_json().encode())
            except OSError:
                return
            sequence += 1
            await asyncio.sleep(0.1)

    task = asyncio.create_task(heartbeats())
    started = time.monotonic()
    try:
        await asyncio.wait_for(owner.stop(), 7)
        assert time.monotonic() - started < 7
        assert owner.state == "ERROR"
        assert owner.last_error == "STREAM_STOP_DEADLINE_EXCEEDED"
        assert owner.metrics["finalization"] == "BLOCKED"
        assert owner.metrics["final_counter_status"] == "UNKNOWN"
        assert not owner.capture.completion_verified()
    finally:
        client.close()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await owner.stop(abort=True)
