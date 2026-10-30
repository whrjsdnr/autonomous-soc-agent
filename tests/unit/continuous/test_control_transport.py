"""Real ordinary UNIX sockets/threads, no Root or Kernel operation."""

import asyncio
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from soc_agent.continuous.native.service import ControlTransport
from soc_agent.continuous.tcx_producer import TCXProducer


@pytest.mark.asyncio
async def test_control_survives_slow_data_work_and_accepts_stop_without_worker_progress():
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    stop = threading.Event()
    transport = ControlTransport("net:[4026532232]", "a" * 64, stop.set)
    transport.stage("INSTALLED_INTEGRITY", 42)
    transport.attach(peer)
    source = TCXProducer(SimpleNamespace(queue_capacity=32, input_sha256="a" * 64))
    source.socket = owner
    loop = asyncio.get_running_loop()
    policy = {"namespace": "net:[4026532232]", "files": {"continuous.bpf.o": "b" * 64}}
    try:
        # Worker performs no progress at all for >3 sec. No data, counters, lease
        # or seal is fabricated by the control thread to pass the receive bound.
        started = time.monotonic()
        for _ in range(4):
            raw = source.envelope(await source.receive_message(loop), policy)
            source.control_record(raw)
            assert raw["worker"]["stage"] == "INSTALLED_INTEGRITY"
            assert "frames" not in raw and "seal" not in raw
        assert time.monotonic() - started >= 3
        assert source.received == 0 and source.epoch is None
        transport.send(json.dumps(dict(generation=42)).encode())
        assert json.loads(await loop.sock_recv(owner, 262145))["generation"] == 42
        transport.stage("WINDOW_ATTACH", None)  # Not yet advertised to the consumer.
        await loop.sock_sendall(
            owner,
            json.dumps(
                dict(operation="STOP_CAPTURE", generation=42, policy_sha256="a" * 64)
            ).encode(),
        )
        assert await asyncio.to_thread(stop.wait, 1)
        assert transport.failure is None
    finally:
        transport.close()
        await source.close()
        peer.close()
    assert not transport.thread.is_alive()


def control(sequence=1, *, age=0, clock=None):
    now = time.monotonic_ns()
    return dict(
        contract="soc-continuous-tcx-control:v1",
        namespace="net:[4026532232]",
        policy_sha256="a" * 64,
        sequence=sequence,
        clock=clock or [now, time.time_ns(), now],
        worker=dict(stage="SQLITE_OR_FILE_FIXTURE", started_monotonic_ns=now - age),
    )


def test_worker_stall_is_distinct_from_process_transport_liveness():
    source = TCXProducer(SimpleNamespace())
    with pytest.raises(ValueError, match="PRODUCER_WORKER_STALE"):
        source.control_record(control(age=5_000_000_001))
    assert source.failure["stage"] == "ROOT_WORKER_PROGRESS"
    assert source.failure["control"]["worker"]["stage"] == "SQLITE_OR_FILE_FIXTURE"
    assert source.failure["timeout_seconds"] == 5
    assert source.failure["capture_restarted"] is False
    assert source.received == 0


def test_control_replay_clock_regression_and_other_policy_are_rejected():
    source = TCXProducer(SimpleNamespace(input_sha256="a" * 64))
    raw = control()
    source.control_record(raw)
    with pytest.raises(ValueError, match="CONTROL_SEQUENCE_OR_CLOCK"):
        source.control_record(raw)
    with pytest.raises(ValueError, match="CONTROL_SEQUENCE_OR_CLOCK"):
        source.control_record(control(2, clock=[1, time.time_ns(), 1]))
    policy = {"namespace": "net:[4026532232]"}
    with pytest.raises(ValueError, match="ACK_BINDING"):
        source.envelope(json.dumps(control() | {"policy_sha256": "c" * 64}).encode(), policy)


@pytest.mark.asyncio
async def test_control_never_occupies_bounded_data_queue():
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    source = TCXProducer(SimpleNamespace(queue_capacity=1, input_sha256="a" * 64))
    source.socket = owner
    loop = asyncio.get_running_loop()
    policy = {"namespace": "net:[4026532232]", "files": {"continuous.bpf.o": "b" * 64}}
    messages = source.messages(loop, policy)
    pending = asyncio.create_task(anext(messages))
    try:
        for i in range(1, 21):
            await loop.sock_sendall(peer, json.dumps(control(i)).encode())
            await asyncio.sleep(0)
        ack = dict(
            contract="soc-continuous-tcx-stop:v1",
            namespace=policy["namespace"],
            policy_sha256="a" * 64,
            generation=42,
            cleanup="VERIFIED",
        )
        await loop.sock_sendall(peer, json.dumps(ack).encode())
        assert await asyncio.wait_for(pending, 2) == ack
        assert source.receiver_dropped_batches == 0
        assert source.last_control_sequence == 20
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        await messages.aclose()
        await source.close()
        peer.close()


@pytest.mark.asyncio
async def test_worker_stall_failure_still_collects_same_channel_stop_ack(monkeypatch):
    from tests.unit.continuous.test_tcx_failure_cleanup import ack, command, message, send, setup

    source, peer = await setup(monkeypatch)

    async def root():
        await send(peer, message(1))
        until = time.monotonic() + 2
        while source.epoch is None and time.monotonic() < until:
            await asyncio.sleep(0.01)
        assert source.epoch == 7
        raw = control(age=5_100_000_000) | {"policy_sha256": "b" * 64}
        await send(peer, raw)
        await command(peer)
        # A repeated stale heartbeat after failed admission is diagnostic only.
        await send(peer, raw)
        await send(peer, message(2, sealed=True))
        await send(peer, ack())

    sender = asyncio.create_task(root())
    try:
        with pytest.raises(ValueError, match="PRODUCER_WORKER_STALE"):
            assert [event async for event in source.events()] == []
        await sender
        assert source.failure["stage"] == "ROOT_WORKER_PROGRESS"
        assert source.cleanup_evidence["status"] == "VERIFIED"
        assert source.cleanup_evidence["stop_ack"]
        assert (
            source.cleanup_evidence["last_control"]["worker"]["stage"] == "SQLITE_OR_FILE_FIXTURE"
        )
        assert len(source.cleanup_evidence["seals"]) == 1
        assert source.cleanup_evidence["global_kernel_cleanup"] == "UNKNOWN"
        assert source.socket is None
    finally:
        await source.close()
        peer.close()
        await asyncio.gather(sender, return_exceptions=True)


def test_buffered_old_control_cannot_extend_liveness_or_claim_low_latency():
    source = TCXProducer(SimpleNamespace())
    now = time.monotonic_ns()
    with pytest.raises(ValueError, match="CONTROL_FRESHNESS"):
        source.control_record(
            control(
                clock=[now - 6_000_000_000, time.time_ns(), now - 6_000_000_000], age=7_000_000_000
            )
        )
    assert source.last_control_sequence is None and source.control_snapshot is None
