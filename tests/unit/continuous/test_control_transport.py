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


@pytest.mark.asyncio
async def test_slow_data_validation_does_not_block_control_heartbeat(monkeypatch):
    """Data preparation must not hold the shared control critical section."""
    from soc_agent.continuous.native import service

    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    transport = ControlTransport("net:[4026532232]", "a" * 64, lambda: None)
    transport.attach(peer)
    loop = asyncio.get_running_loop()
    entered, release = threading.Event(), threading.Event()
    body = b'{"generation":42}'
    original = json.loads
    failures = []

    def slow_decode(value, *args, **kwargs):
        if value == body:
            entered.set()
            if not release.wait(4):
                raise TimeoutError("DATA_VALIDATION_FIXTURE_BOUND")
        return original(value, *args, **kwargs)

    def send():
        try:
            transport.send(body)
        except BaseException as error:
            failures.append(error)

    sender = threading.Thread(target=send)
    try:
        first = original(await asyncio.wait_for(loop.sock_recv(owner, 262145), 2))
        assert first["contract"] == "soc-continuous-tcx-control:v1"
        monkeypatch.setattr(service.json, "loads", slow_decode)
        sender.start()
        assert await asyncio.to_thread(entered.wait, 1)
        next_record = original(await asyncio.wait_for(loop.sock_recv(owner, 262145), 2))
        assert next_record["contract"] == "soc-continuous-tcx-control:v1"
        assert next_record["sequence"] == first["sequence"] + 1
        assert sender.is_alive() and transport.advertised_generation is None
    finally:
        release.set()
        await asyncio.to_thread(sender.join, 2)
        transport.close()
        owner.close()
        peer.close()
    assert not sender.is_alive() and not failures
    assert transport.advertised_generation == 42


def test_invalid_data_is_rejected_before_socket_publication():
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    transport = ControlTransport("net:[4026532232]", "a" * 64, lambda: None)
    transport.attach(peer)
    try:
        with pytest.raises(KeyError, match="generation"):
            transport.send(b"{}")
        transport.close()
        records = []
        while True:
            try:
                records.append(json.loads(owner.recv(262145)))
            except BlockingIOError:
                break
        assert all(row.get("contract") == "soc-continuous-tcx-control:v1" for row in records)
        assert transport.advertised_generation is None
    finally:
        transport.close()
        owner.close()
        peer.close()


@pytest.mark.asyncio
async def test_initial_accept_does_not_wait_for_data_worker(tmp_path):
    """Exercise a real listening socket while the data worker makes no progress."""
    import os

    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(str(tmp_path / "control.sock"))
    server.listen(1)
    server.setblocking(False)
    client.setblocking(False)
    stopped = threading.Event()
    transport = ControlTransport("net:[4026532232]", "a" * 64, stopped.set)
    transport.stage("INSTALLED_INTEGRITY", 42)
    transport.listen(server, os.getuid())
    loop = asyncio.get_running_loop()
    try:
        await loop.sock_connect(client, str(tmp_path / "control.sock"))
        for sequence in range(1, 4):
            raw = json.loads(await asyncio.wait_for(loop.sock_recv(client, 262145), 2))
            assert raw["sequence"] == sequence
            assert raw["worker"]["stage"] == "INSTALLED_INTEGRITY"
            assert raw["peer_identity"]["uid"] == os.getuid()
            assert raw["peer_identity"]["pid"] == os.getpid()
            assert "frames" not in raw and "seal" not in raw
        await loop.sock_sendall(
            client,
            json.dumps(
                dict(
                    operation="STOP_CAPTURE",
                    generation=None,
                    policy_sha256="a" * 64,
                )
            ).encode(),
        )
        assert await asyncio.to_thread(stopped.wait, 1)
        assert transport.connected_peer() is not None
        assert transport.advertised_generation is None
    finally:
        transport.close()
        if transport.connected_peer() is not None:
            transport.connected_peer().close()
        client.close()
        server.close()


@pytest.mark.asyncio
async def test_initial_accept_rejects_other_uid_without_heartbeat(tmp_path):
    import os

    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(str(tmp_path / "rejected.sock"))
    server.listen(1)
    server.setblocking(False)
    client.setblocking(False)
    transport = ControlTransport("net:[4026532232]", "a" * 64, lambda: None)
    transport.listen(server, os.getuid() + 1)
    loop = asyncio.get_running_loop()
    try:
        await loop.sock_connect(client, str(tmp_path / "rejected.sock"))
        assert await asyncio.wait_for(loop.sock_recv(client, 262145), 2) == b""
        assert transport.connected_peer() is None
        assert transport.accepted_identity is None
        assert transport.sequence == 0
    finally:
        transport.close()
        client.close()
        server.close()
