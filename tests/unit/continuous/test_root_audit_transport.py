"""Ordinary files and UNIX transport only; no Root, BPF or traffic generation."""

import asyncio
import errno
import json
import os
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from soc_agent.continuous.native import service
from soc_agent.continuous.tcx_producer import TCXProducer


def writer(tmp_path):
    path = tmp_path / "audit.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return path, service.OrderedAudit(fd, "0" * 64)


@pytest.mark.asyncio
async def test_delayed_fsync_does_not_starve_authenticated_transport_and_seal_waits(
    tmp_path, monkeypatch
):
    entered, release = threading.Event(), threading.Event()
    original = os.fsync
    held_fd = None

    def delayed(fd):
        if fd == held_fd and not release.is_set():
            entered.set()
            assert release.wait(10)
        original(fd)

    monkeypatch.setattr(service.os, "fsync", delayed)
    path, audit = writer(tmp_path)
    held_fd = audit.fd
    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    source = TCXProducer(SimpleNamespace(queue_capacity=32))
    source.socket = owner
    loop = asyncio.get_running_loop()
    audit.record("HEARTBEAT", {"sequence": 0}, wait=False)
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        began = time.monotonic()
        for i in range(16):
            audit.check()
            body = json.dumps({"sequence": i, "audit_pending": audit.pending}).encode()
            await loop.sock_sendall(peer, body)
            assert json.loads(await source.receive_message(loop))["sequence"] == i
            await asyncio.sleep(0.4)
        assert time.monotonic() - began > 6  # Original receive timeout remains five seconds.
        assert audit.committed == 0 and audit.pending == 1
        seal = asyncio.create_task(asyncio.to_thread(audit.record, "CAPTURE_WINDOW_SEALED", {}))
        await asyncio.sleep(0.05)
        assert not seal.done()  # Pending audit cannot authorize a sealed window.
        release.set()
        await asyncio.wait_for(seal, 2)
        assert audit.pending == 0 and audit.committed == 2
        audit.close()
        rows = path.read_bytes().splitlines(keepends=True)
        assert service.audit_tail(iter(rows)) == audit.previous
        assert [json.loads(row)["code"] for row in rows] == ["HEARTBEAT", "CAPTURE_WINDOW_SEALED"]
    finally:
        release.set()
        audit.close()
        await source.close()
        peer.close()
    assert source.failure is None and not audit.thread.is_alive()


def test_write_failure_preserves_errno_and_closes_owned_descriptor(tmp_path, monkeypatch):
    path, audit = writer(tmp_path)

    def full(fd):
        if fd == audit.fd:
            raise OSError(errno.ENOSPC, "fixture disk full")

    monkeypatch.setattr(service.os, "fsync", full)
    with pytest.raises(ValueError, match="AUDIT_WRITE_FAILED") as result:
        audit.record("ATTACH_REQUESTED", {})
    assert result.value.__cause__.errno == errno.ENOSPC
    with pytest.raises(ValueError, match="AUDIT_WRITE_FAILED"):
        audit.close()
    assert path.exists() and not audit.thread.is_alive()
    with pytest.raises(OSError):
        os.fstat(audit.fd)


def test_bounded_queue_fails_closed_and_drain_keeps_hash_chain(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = os.fsync
    path, audit = writer(tmp_path)

    def delayed(fd):
        if fd == audit.fd:
            entered.set()
            assert release.wait(2)
        original(fd)

    monkeypatch.setattr(service.os, "fsync", delayed)
    try:
        audit.record("HEARTBEAT", {}, wait=False)
        assert entered.wait(1)
        for i in range(8):
            audit.record("HEARTBEAT", {"i": i}, wait=False)
        with pytest.raises(ValueError, match="AUDIT_BACKPRESSURE"):
            audit.record("HEARTBEAT", {}, wait=False)
        assert audit.pending == 9
    finally:
        release.set()
        audit.close()
    assert audit.pending == 0 and audit.committed == 9
    assert service.audit_tail(iter(path.read_bytes().splitlines(keepends=True))) == audit.previous


def test_partial_append_cannot_be_accepted_as_a_durable_barrier(tmp_path, monkeypatch):
    path, audit = writer(tmp_path)
    original = os.write

    def partial(fd, body):
        if fd == audit.fd:
            return original(fd, body[:-1])
        return original(fd, body)

    monkeypatch.setattr(service.os, "write", partial)
    with pytest.raises(ValueError, match="AUDIT_WRITE_FAILED") as result:
        audit.record("CAPTURE_WINDOW_SEALED", {})
    assert str(result.value.__cause__) == "CONTINUOUS_ROOT_AUDIT_PARTIAL"
    with pytest.raises(ValueError, match="AUDIT_WRITE_FAILED"):
        audit.close()
    assert audit.committed == 0 and not audit.thread.is_alive()
    with pytest.raises(ValueError, match="AUDIT_PARTIAL_OR_BOUND"):
        service.audit_tail(iter(path.read_bytes().splitlines(keepends=True)))
