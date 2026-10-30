"""Production receiver/service over ordinary Unix sockets; Root connect only is mocked.

All packet/seal evidence here is FIXTURE. No Kernel, DNS, model or API call.
"""

import asyncio
import json
import os
import socket
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from tests.unit.continuous.test_capture_admission import reseal, transcript
from tests.unit.continuous.test_runtime import make

from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.store import Store
from soc_agent.continuous.tcx_producer import TCXProducer
from soc_agent.security_ai.ebpf.ring import ABI
from soc_agent.security_ai.research.models import digest

NS = "net:[4026532232]"
POLICY = dict(uid=os.getuid(), namespace=NS, files={"continuous.bpf.o": "a" * 64})


def fixture_wire():
    e = transcript()[1][0]
    return ABI.pack(
        e.generation,
        e.timestamp_ns,
        e.cpu_sequence,
        e.ifindex,
        e.cpu,
        e.frame_length,
        e.ip_length,
        e.source_port,
        e.destination_port,
        4,
        17,
        e.tcp_flags,
        1,
        e.source.packed.ljust(16, b"\0"),
        e.destination.packed.ljust(16, b"\0"),
    ).hex()


def message(sequence, *, frames=(), sealed=False):
    raw = dict(
        contract="soc-continuous-tcx:v1",
        namespace=NS,
        ifindex=1,
        generation=7,
        program_sha256="a" * 64,
        sequence=sequence,
        clock=[100, 1000, 102],
        state=dict(state="SEALED" if sealed else "RUNNING", counters={}),
        frames=list(frames),
    )
    if sealed:
        body = transcript()[0].model_dump(mode="json")
        body["release_manifest"] = digest(POLICY["files"])
        raw["seal"] = reseal(body).model_dump(mode="json")
    return raw


def ack(**updates):
    return (
        dict(
            contract="soc-continuous-tcx-stop:v1",
            namespace=NS,
            generation=7,
            policy_sha256="b" * 64,
            cleanup="VERIFIED",
        )
        | updates
    )


async def setup(monkeypatch):
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    source = TCXProducer(
        SimpleNamespace(
            namespace=NS,
            queue_capacity=32,
            input_sha256="b" * 64,
        )
    )

    async def connect(loop):
        source.socket = owner
        source.peer_identity = dict(pid=os.getpid(), uid=0, gid=0, start_ticks="fixture")

    monkeypatch.setattr(source, "connect", connect)
    monkeypatch.setattr("soc_agent.continuous.tcx_producer.installed", lambda: POLICY)
    return source, peer


async def send(peer, raw):
    await asyncio.get_running_loop().sock_sendall(peer, json.dumps(raw).encode())


async def command(peer):
    raw = json.loads(await asyncio.get_running_loop().sock_recv(peer, 4096))
    assert raw == dict(operation="STOP_CAPTURE", generation=7, policy_sha256="b" * 64)


def immediate_timeout_after_first(monkeypatch, source):
    receive = source.receive_message
    failed = False

    async def delayed(loop):
        nonlocal failed
        await asyncio.sleep(0.02)
        if source.epoch is not None and not failed:
            failed = True
            return await receive(SimpleNamespace(sock_recv=AsyncMock(side_effect=TimeoutError)))
        return await receive(loop)

    monkeypatch.setattr(source, "receive_message", delayed)


@pytest.mark.asyncio
async def test_real_timeout_stops_on_same_channel_and_quarantines_late_seal(monkeypatch):
    source, peer = await setup(monkeypatch)
    ready = asyncio.Event()
    admitted = []

    async def root():
        await send(peer, message(1, frames=["00"]))
        ready.set()
        await command(peer)  # Receive timeout must produce STOP, not close/disconnect.
        assert source.failure["code"] == "CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"
        assert source.snapshot["failure"] == source.failure
        await asyncio.sleep(0.15)  # A delayed ACK/seal remains inside its own bounded drain.
        await send(peer, message(2, frames=["01"], sealed=True))
        await send(peer, ack())

    sender = asyncio.create_task(root())
    try:
        with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"):
            async for raw in source.events():
                admitted.append(raw)
        await sender
        assert ready.is_set() and len(admitted) == 1
        assert admitted[0]["kind"] == "native_tcx"
        assert source.failure["wait_elapsed_seconds"] >= 4.9
        assert source.failure["last_message_age_monotonic_seconds"] >= 4.9
        assert source.failure["origin"][-1]["function"] == "receive_message"
        proof = source.cleanup_evidence
        assert proof["status"] == "VERIFIED" and proof["stop_ack"]
        assert proof["receiver_joined"] and proof["socket_closed"]
        assert proof["quarantined_events"] == 1 and len(proof["seals"]) == 1
        assert proof["admission"] == "BLOCKED_FAILED_STREAM"
        assert proof["global_kernel_cleanup"] == "UNKNOWN"
        assert 0.15 <= proof["elapsed_seconds"] < 5
        assert source.stop_ack.is_set() and source.socket is None
    finally:
        await source.close()
        peer.close()
        await asyncio.gather(sender, return_exceptions=True)


@pytest.mark.asyncio
async def test_quiet_data_with_heartbeats_is_not_packet_timeout(monkeypatch):
    source, peer = await setup(monkeypatch)

    async def root():
        for seq in range(1, 8):
            await send(peer, message(seq))
            await asyncio.sleep(0.85)
        await send(peer, message(8, sealed=True))
        await send(peer, ack())

    sender = asyncio.create_task(root())
    try:
        records = [raw async for raw in source.events()]
        await sender
        assert [r["kind"] for r in records] == ["native_seal"]
        assert source.failure is None and source.received == 0
        assert source.last_data_monotonic is None
        assert source.last_validated_monotonic is not None
        assert source.remote_cleanup == "VERIFIED"
    finally:
        peer.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["namespace", "policy", "epoch", "sequence", "counter", "seal"])
async def test_cleanup_reuses_security_checks_and_never_overwrites_timeout(monkeypatch, fault):
    source, peer = await setup(monkeypatch)
    immediate_timeout_after_first(monkeypatch, source)

    async def root():
        await send(peer, message(1, frames=["00"]))
        await command(peer)
        bad = message(2, sealed=True)
        if fault == "sequence":
            bad["sequence"] = 99
        elif fault == "counter":
            bad["state"]["counters"] = {"0": [-1, 1, 0, 0, 0, 0, 0]}
        elif fault == "seal":
            bad["seal"]["seal_sha256"] = "0" * 64
        else:
            key = {"namespace": "namespace", "policy": "policy_sha256", "epoch": "generation"}[
                fault
            ]
            value = {"namespace": "net:[1]", "policy": "0" * 64, "epoch": 8}[fault]
            await send(peer, ack(**{key: value}))
            return
        await send(peer, bad)

    sender = asyncio.create_task(root())
    stream = source.events()
    try:
        assert (await anext(stream))["kind"] == "native_tcx"
        # Let the real background receiver consume the injected timeout.
        with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"):
            await anext(stream)
        await sender
        assert source.failure["code"] == "CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"
        assert source.cleanup_evidence["status"] == "UNVERIFIED"
        assert not source.stop_ack.is_set() and source.remote_cleanup == "UNKNOWN"
    finally:
        await stream.aclose()
        peer.close()
        sender.cancel()
        await asyncio.gather(sender, return_exceptions=True)


@pytest.mark.asyncio
async def test_missing_ack_is_bounded_and_partial_window_stays_unverified(monkeypatch):
    source, peer = await setup(monkeypatch)
    await send(peer, message(1, frames=["00"]))
    stream = source.events()
    first = await anext(stream)
    assert first["kind"] == "native_tcx"
    began = time.monotonic()
    # Consumer failure/cancellation uses the same production finalizer.
    pending = asyncio.create_task(stream.aclose())
    await command(peer)
    await pending
    assert 4.9 <= time.monotonic() - began < 6.5
    assert source.cleanup_evidence["status"] == "UNVERIFIED"
    assert source.cleanup_evidence["error"]["code"] == "CONTINUOUS_STOP_ACK_TIMEOUT"
    assert source.cleanup_evidence["seals"] == []
    assert source.remote_cleanup == "UNKNOWN" and source.socket is None
    peer.close()


@pytest.mark.asyncio
async def test_peer_exit_is_not_relabelled_as_quiet_traffic(monkeypatch):
    source, peer = await setup(monkeypatch)
    stream = source.events()
    await send(peer, message(1, frames=[fixture_wire()]))
    assert (await anext(stream))["kind"] == "native_tcx"
    peer.close()
    with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_DISCONNECTED"):
        await anext(stream)
    assert source.failure["code"] == "CONTINUOUS_PRODUCER_DISCONNECTED"
    assert source.cleanup_evidence["status"] == "UNVERIFIED"
    assert source.remote_cleanup == "UNKNOWN" and source.socket is None


@pytest.mark.asyncio
async def test_interrupted_cleanup_still_closes_owned_socket(monkeypatch):
    source, peer = await setup(monkeypatch)
    stream = source.events()
    await send(peer, message(1, frames=[fixture_wire()]))
    assert (await anext(stream))["kind"] == "native_tcx"
    ending = asyncio.create_task(stream.aclose())
    await command(peer)
    ending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await ending
    assert source.cleanup_evidence["error"]["code"] == "CONTINUOUS_CLEANUP_CANCELLED"
    assert source.cleanup_evidence["status"] == "UNVERIFIED"
    assert source.remote_cleanup == "UNKNOWN" and source.socket is None
    assert source.cleanup_evidence["receiver_joined"]
    peer.close()


@pytest.mark.asyncio
async def test_batch_tail_cannot_enter_runtime_after_background_timeout(monkeypatch):
    source, peer = await setup(monkeypatch)
    immediate_timeout_after_first(monkeypatch, source)

    async def root():
        await send(peer, message(1, frames=[fixture_wire(), fixture_wire()]))
        await command(peer)
        await send(peer, message(2, sealed=True))
        await send(peer, ack())

    sender = asyncio.create_task(root())
    stream = source.events()
    try:
        assert (await anext(stream))["kind"] == "native_tcx"
        async with asyncio.timeout(2):
            while source.failure is None:
                await asyncio.sleep(0.01)
        with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"):
            await anext(stream)
        await sender
        assert source.cleanup_evidence["quarantined_events"] == 1
        assert len(source.cleanup_evidence["seals"]) == 1
        assert source.remote_cleanup == "VERIFIED"
    finally:
        await stream.aclose()
        peer.close()
        sender.cancel()
        await asyncio.gather(sender, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["retain", "applied"])
async def test_actual_native_projection_keeps_receiver_live_during_durability(
    monkeypatch,
    tmp_path,
    operation,
):
    source, peer = await setup(monkeypatch)
    directory, _ = make(tmp_path)
    runtime = ContinuousRuntime(directory, source=source)
    runtime.config = runtime.config.model_copy(update={"source": "NATIVE_SERVICE"})
    entered, release = threading.Event(), threading.Event()
    original = getattr(runtime.store, operation)

    def durable(*args):
        entered.set()
        assert release.wait(3)
        return original(*args)

    monkeypatch.setattr(runtime.store, operation, durable)
    stream = source.events()
    await send(peer, message(1, frames=[fixture_wire()]))
    event = await anext(stream)
    projected = asyncio.create_task(runtime.observe(event))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        stamp = source.last_message_monotonic
        await send(peer, message(2))
        async with asyncio.timeout(1):
            while source.last_message_monotonic == stamp:
                await asyncio.sleep(0.01)
        assert not projected.done() and source.failure is None
        release.set()
        await projected
        await send(peer, ack())
        assert [r async for r in stream] == []
        assert runtime.metrics["native_events"] == 1
        assert len(runtime.capture_windows.events) == 1
        assert source.remote_cleanup == "VERIFIED"
    finally:
        release.set()
        await asyncio.gather(projected, return_exceptions=True)
        await stream.aclose()
        peer.close()


@pytest.mark.asyncio
async def test_runtime_entry_preserves_primary_and_durable_cleanup(monkeypatch, tmp_path):
    source, peer = await setup(monkeypatch)
    immediate_timeout_after_first(monkeypatch, source)
    directory, store = make(tmp_path)
    runtime = ContinuousRuntime(directory, source=source)
    runtime.config = runtime.config.model_copy(update={"source": "NATIVE_SERVICE"})
    monkeypatch.setattr("soc_agent.continuous.service.require_source_authority", lambda _: None)

    async def root():
        await send(peer, message(1, frames=[fixture_wire()]))
        await command(peer)
        live = runtime.snapshot()
        assert live["state"] == "DEGRADED" and not live["collection_live"]
        assert live["last_error"] == "CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"
        await send(peer, message(2, sealed=True))
        await send(peer, ack())

    sender = asyncio.create_task(root())
    try:
        with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"):
            await asyncio.wait_for(runtime.run(), 8)
        await sender
        state = store.state()
        assert state["collector_cleanup"] == state["cleanup"] == "VERIFIED"
        assert state["producer"]["cleanup_evidence"]["admission"] == "BLOCKED_FAILED_STREAM"
        assert "CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT" in state["last_error"]
        assert runtime.metrics["predictions"] == 0
        assert runtime.capture_windows.last_window is None
        assert len(runtime.capture_windows.events) == 1
        assert store.queue.counts() == {}
        # Audit row is durable and independently stores the aborted seal and ACK.
        import sqlite3

        with sqlite3.connect(directory / "service.sqlite") as db:
            rows = db.execute("SELECT * FROM external_security_audit").fetchall()
        assert any("CONTINUOUS_TCX_CLEANUP_EVIDENCE" in str(row) for row in rows)
        assert runtime.metrics["collector_restarts"] == 0
        with pytest.raises(ValueError, match="SESSION_REUSE_FORBIDDEN"):
            await anext(source.events())
    finally:
        runtime.stop.set()
        peer.close()
        sender.cancel()
        await asyncio.gather(sender, return_exceptions=True)


@pytest.mark.asyncio
async def test_operating_cli_child_exit_and_failure_evidence(tmp_path):
    """Actual CLI child and persistence; only Root authority/endpoint is a fixture."""
    from tests.unit.continuous.test_runtime import config

    from soc_agent.continuous.cli import code_identity

    directory = tmp_path / "cli-child"
    store = Store.create(
        directory,
        config(tmp_path).model_copy(
            update=dict(
                source="NATIVE_SERVICE",
                input_sha256="b" * 64,
            )
        ),
    )
    (directory / "code-identity").write_text(code_identity())
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    peer.setblocking(False)
    script = """
import os, socket, sys
from soc_agent.continuous import cli, service, tcx_producer
policy = dict(uid=os.getuid(), namespace='net:[4026532232]', files={'continuous.bpf.o': 'a'*64})
service.require_source_authority = lambda config: None  # Root authority fixture only
tcx_producer.installed = lambda: policy
async def connect(self, loop):
    self.socket = socket.socket(fileno=int(sys.argv[2]))
    self.socket.setblocking(False)  # Root endpoint fixture only
tcx_producer.TCXProducer.connect = connect
raise SystemExit(cli.main(['run', sys.argv[1]]))
"""
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        script,
        str(directory),
        str(owner.fileno()),
        pass_fds=(owner.fileno(),),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    owner.close()
    try:
        await send(peer, message(1, frames=[fixture_wire()]))
        await asyncio.wait_for(command(peer), 12)
        await send(peer, message(2, sealed=True))
        await send(peer, ack())
        stdout, stderr = await asyncio.wait_for(child.communicate(), 10)
        result = json.loads(stdout)
        assert child.returncode == 2 and stderr == b""
        assert result["error"] == "ValueError:CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"
        assert result["status"] == "FAILED_OR_BLOCKED"
        assert result["executed"] is None  # Failure must not deny the observed capture.
        assert result["execution_evidence_directory"] == str(directory)
        state = store.state()
        assert state["collector_cleanup"] == state["cleanup"] == "VERIFIED"
        assert state["capture_window"]["assessment"]["status"] != "VERIFIED"
        assert state["metrics"]["predictions"] == state["metrics"]["collector_restarts"] == 0
        (directory / "cli-child-result.json").write_text(
            json.dumps(
                dict(
                    evidence="FIXTURE_ROOT_ENDPOINT_NOT_LIVE_NATIVE",
                    returncode=child.returncode,
                    result=result,
                    cleanup=state["cleanup"],
                    stop_ack=state["producer"]["cleanup_evidence"]["stop_ack"],
                )
            )
        )
    finally:
        peer.close()
        if child.returncode is None:
            child.terminate()
            await asyncio.wait_for(child.wait(), 15)
