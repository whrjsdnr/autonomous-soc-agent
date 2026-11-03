"""Diagnostic classification over private UNIX sockets; no Root/TCX/DNS/API."""

import asyncio
import errno
import json
import os
import socket
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from soc_agent.continuous.native.service import (
    ControlTransport,
    OrderedAudit,
    audit_tail,
    socket_diagnostics,
)
from soc_agent.continuous.tcx_producer import TCXProducer


def sockets():
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    return owner, peer


@pytest.mark.asyncio
async def test_sender_generation_send_and_durable_trace_have_distinct_times(tmp_path):
    owner, peer = sockets()
    transport = ControlTransport("net:[4026532232]", "a" * 64, lambda: None)
    transport.attach(peer)
    try:
        loop = asyncio.get_running_loop()
        first = json.loads(await asyncio.wait_for(loop.sock_recv(owner, 262145), 2))
        second = json.loads(await asyncio.wait_for(loop.sock_recv(owner, 262145), 2))
        assert first["sequence"] == 1 and second["sequence"] == 2
        previous = second["transport_trace"]["previous_send"]
        assert previous["channel"] == "CONTROL" and previous["sequence"] == 1
        assert first["clock"][2] <= previous["send_started_ns"] <= previous["send_completed_ns"]
        assert previous["send_completed_ns"] <= second["clock"][0]
        assert previous["outcome"] == "SENT"
        assert second["transport_identity"]["pid"] == os.getpid()
        assert previous["socket"]["nonblocking"] is True
    finally:
        transport.close()
        owner.close()
        peer.close()
    evidence = transport.diagnostics()
    assert evidence["thread_alive"] is False
    assert evidence["send_totals"]["SENT"] >= 2
    path = tmp_path / "audit.jsonl"
    writer = OrderedAudit(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "0" * 64)
    writer.record("CONTROL_TRANSPORT_DIAGNOSTICS", evidence)
    writer.close()
    rows = path.read_bytes().splitlines(keepends=True)
    assert audit_tail(rows) == json.loads(rows[-1])["sha256"]
    assert "DIAGNOSTIC_ONLY" in evidence["permission"]
    assert "frames" not in evidence and "cleanup" not in evidence


def test_real_socket_backpressure_is_counted_without_retry_or_data_consumption():
    owner, peer = sockets()
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    transport = ControlTransport("net:[4026532232]", "a" * 64, lambda: None)
    transport.attach(peer)
    try:
        for sequence in range(1000):
            try:
                transport.send(json.dumps(dict(generation=42, sequence=sequence)).encode())
            except BlockingIOError as error:
                assert error.errno in (errno.EAGAIN, errno.EWOULDBLOCK)
                break
        else:
            pytest.fail("Private socket did not reach bounded send capacity")
        transport.close()
        evidence = transport.diagnostics()
        assert evidence["send_totals"]["BACKPRESSURE"] > 0
        assert any(row["outcome"] == "BACKPRESSURE" for row in evidence["trace"])
        before = socket_diagnostics(owner)
        after = socket_diagnostics(owner)
        assert before["fionread_bytes"] == after["fionread_bytes"] > 0
        assert before["receive_buffer"] > 0
        assert owner.recv(262145)  # Observation did not read or discard the record.
    finally:
        transport.close()
        owner.close()
        peer.close()


@pytest.mark.asyncio
async def test_shared_lock_delay_is_recorded_separately_from_send_duration():
    owner, peer = sockets()
    transport = ControlTransport("net:[4026532232]", "a" * 64, lambda: None)
    transport.attach(peer)
    try:
        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_recv(owner, 262145), 2)
        with transport.lock:
            await asyncio.sleep(1.1)  # Fixture-only lock contention; contract unchanged.
        second = json.loads(await asyncio.wait_for(loop.sock_recv(owner, 262145), 2))
        assert second["sequence"] == 2
        transport.close()
        row = next(r for r in transport.diagnostics()["trace"] if r["sequence"] == 2)
        assert row["lock_acquired_ns"] - row["lock_requested_ns"] > 900_000_000
        assert row["send_started_ns"] <= row["send_completed_ns"]
        assert row["outcome"] == "SENT"
    finally:
        transport.close()
        owner.close()
        peer.close()


def test_cpu_counter_snapshots_are_fixture_measurements_not_risk_decisions(tmp_path):
    transport = ControlTransport("net:[4026532232]", "a" * 64, lambda: None)
    try:
        for value in (100, 900):
            (tmp_path / "cpu.stat").write_text(
                f"usage_usec {value}\nnr_periods 50\nnr_throttled 10\nthrottled_usec {value}\n"
            )
            transport.sample_cpu(tmp_path)
        transport.sample_cpu(tmp_path / "missing")
        rows = transport.diagnostics()["cpu_samples"]
        assert rows[1]["cpu_stat"]["throttled_usec"] - rows[0]["cpu_stat"]["throttled_usec"] == 800
        assert rows[2]["status"] == "UNKNOWN"
        assert all(r["started_monotonic_ns"] <= r["completed_monotonic_ns"] for r in rows)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_timeout_records_unread_ipc_but_never_renews_the_five_second_deadline():
    owner, peer = sockets()
    source = TCXProducer(SimpleNamespace())
    source.socket = owner
    payload = b"FIXTURE_UNREAD_NOT_AN_APPROVED_CAPTURE_RECORD"
    peer.send(payload)
    try:
        with pytest.raises(ValueError, match="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"):
            await source.receive_message(
                SimpleNamespace(sock_recv=AsyncMock(side_effect=TimeoutError))
            )
        proof = source.failure
        assert proof["timeout_seconds"] == 5
        assert proof["socket_at_timeout"]["fionread_bytes"] == len(payload)
        assert proof["socket_at_timeout"]["nonblocking"] is True
        assert proof["receive_trace"][-1]["outcome"] == "TIMEOUT"
        assert source.received == 0 and not source.stop_ack.is_set()
        assert proof["capture_restarted"] is False
        assert owner.recv(262145) == payload
        assert payload.decode() not in json.dumps(proof)
    finally:
        await source.close()
        peer.close()


@pytest.mark.asyncio
async def test_receiver_retains_bounded_wire_times_without_payload():
    owner, peer = sockets()
    source = TCXProducer(SimpleNamespace())
    source.socket = owner
    try:
        for _ in range(70):
            peer.send(b"FIXTURE_PAYLOAD_NOT_LOGGED")
            assert await source.receive_message(asyncio.get_running_loop())
        assert len(source.receive_trace) == 64
        assert all(
            r["started_monotonic_ns"] <= r["completed_monotonic_ns"] for r in source.receive_trace
        )
        assert "FIXTURE_PAYLOAD_NOT_LOGGED" not in json.dumps(list(source.receive_trace))
    finally:
        await source.close()
        peer.close()


@pytest.mark.asyncio
async def test_malformed_envelope_fields_do_not_become_diagnostic_payload():
    owner, peer = sockets()
    source = TCXProducer(SimpleNamespace(queue_capacity=2))
    source.socket = owner
    policy = dict(namespace="net:[4026532232]", files={"continuous.bpf.o": "b" * 64})
    body = dict(
        contract="soc-continuous-tcx:v1",
        namespace=policy["namespace"],
        ifindex=1,
        program_sha256="b" * 64,
        generation=7,
        clock="FIXTURE_PRIVATE_PAYLOAD",
        sequence=dict(raw="FIXTURE_PRIVATE_PAYLOAD"),
        frames=[],
    )
    stream = source.messages(asyncio.get_running_loop(), policy)
    try:
        peer.send(json.dumps(body).encode())
        await asyncio.wait_for(anext(stream), 2)  # Envelope only, never records()/admission.
        row = source.receive_trace[0]
        assert row["root_clock"] is None and row["sequence"] is None
        assert "FIXTURE_PRIVATE_PAYLOAD" not in json.dumps(list(source.receive_trace))
        assert source.received == 0 and not source.stop_ack.is_set()
    finally:
        await stream.aclose()
        await source.close()
        peer.close()


def test_fionread_reports_kernel_queued_bytes_without_consuming():
    owner, peer = sockets()
    try:
        peer.send(b"AAAA")
        peer.send(b"BBBBBBBB")
        assert socket_diagnostics(owner)["fionread_bytes"] == 12
        assert owner.recv(262145) == b"AAAA"
        assert socket_diagnostics(owner)["fionread_bytes"] == 8
        assert owner.recv(262145) == b"BBBBBBBB"
    finally:
        owner.close()
        peer.close()


def test_diagnostic_unavailable_never_masks_original_send_error():
    class BrokenPeer:
        def send(self, _):
            raise ValueError("ORIGINAL_SEND_ERROR")

    transport = ControlTransport("net:[4026532232]", "a" * 64, lambda: None)
    transport.close()  # No reader can touch the deliberately invalid test peer.
    transport.peer = BrokenPeer()
    with transport.lock, pytest.raises(ValueError, match="ORIGINAL_SEND_ERROR"):
        transport.emit(b"FIXTURE", "DATA", 1, time.monotonic_ns(), time.monotonic_ns())
    proof = transport.diagnostics()
    assert proof["send_totals"]["ERROR"] == 1
    assert proof["trace"][-1]["socket"]["status"] == "UNAVAILABLE"
