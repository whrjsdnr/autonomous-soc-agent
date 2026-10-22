"""Real Unix packet boundaries/credentials; intentionally forged metadata envelopes."""

import array
import os
import socket

import pytest
from tests.unit.ebpf_tc.test_contracts import native_plan
from tests.unit.tcx_data.test_pipeline import raw

from soc_agent.security_ai.ebpf_native.contracts import local_controller
from soc_agent.security_ai.ebpf_tc.data_plane import HEADER, MAGIC, PacketChannel


@pytest.fixture
def channel(tmp_path):
    p = native_plan()
    c = PacketChannel(p, "f" * 64, tmp_path)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    c.channel, c.identity, c.source = left, local_controller(), 2
    yield c, right
    # Bare socketpair fixtures have no C producer/CLOSED protocol.
    left.close()
    right.close()


def frame(c, kind=2, sequence=1, *, change=None, packet=None):
    fields = [
        MAGIC,
        1,
        kind,
        2,
        sequence,
        0,
        c.plan.broker.application.application_session.bytes,
        bytes.fromhex(c.approval),
        bytes.fromhex(c.plan.program_sha256),
    ]
    for index, value in (change or {}).items():
        fields[index] = value
    return HEADER.pack(*fields) + (packet if packet is not None else raw())


@pytest.mark.parametrize(
    "change",
    [
        {0: 1},
        {1: 2},
        {2: 5},
        {3: 1},
        {4: 2},
        {4: 0},
        {5: 1},
        {6: bytes(16)},
        {7: bytes(32)},
        {8: bytes(32)},
    ],
)
def test_identity_sequence_and_loss_fail_closed(channel, change):
    c, peer = channel
    c.prepare_adapter(7)
    peer.send(frame(c, change=change))
    with pytest.raises(ValueError):
        c.pump()
    assert c.error and not c.adapter.network_events()
    assert c.adapter.flow.closed and c.adapter.snapshot()["ebpf"]["native_ai"] == "BLOCKED"


@pytest.mark.parametrize("fault", ["size", "truncated", "rights", "pid_ticks", "eof"])
def test_transport_attacks_never_become_packet_success(channel, tmp_path, fault):
    c, peer = channel
    c.prepare_adapter(7)
    body = frame(c)
    fd = -1
    if fault == "eof":
        peer.shutdown(socket.SHUT_WR)
    elif fault == "rights":
        fd = os.open(tmp_path / "file", os.O_CREAT | os.O_RDWR, 0o600)
        peer.sendmsg([body], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
    else:
        if fault == "pid_ticks":
            c.identity = c.identity.model_copy(update={"start_ticks": c.identity.start_ticks + 1})
        peer.send(
            b"partial" if fault == "size" else body + bytes(100) if fault == "truncated" else body
        )
    before = len(os.listdir("/proc/self/fd"))
    try:
        with pytest.raises(ValueError):
            c.pump()
        assert len(os.listdir("/proc/self/fd")) == before
        assert c.error and c.adapter.accepted == 0
    finally:
        if fd >= 0:
            os.close(fd)


def test_queue_overflow_marks_incomplete_and_unknown_kernel_loss(channel):
    c, peer = channel
    c.prepare_adapter(7)
    for i in range(1, 33):
        c.adapter.ingest(raw(sequence=i), monotonic=c.adapter.last_processing)
    peer.send(frame(c, packet=raw(sequence=33)))
    with pytest.raises(ValueError, match="QUEUE_OVERFLOW"):
        c.pump()
    snap = c.snapshot()
    assert snap["queue_overflows"] == 1 and snap["kernel_drops"] is None
    assert not c.adapter.queue and c.adapter.flow.closed
    # Discard includes the rejected 33rd record and the 32 queued records.
    assert c.adapter.metrics()["queue_discarded"] == c.adapter.received == 33
    assert c.adapter.accepted == 0
    assert c.adapter.metrics()["queue_rejected"] == 1


def test_foreign_interface_generation_and_timestamp_are_rejected(channel):
    c, peer = channel
    c.prepare_adapter(7)
    peer.send(frame(c, packet=raw(generation=99)))
    with pytest.raises(ValueError, match="SOURCE_IDENTITY"):
        c.pump()
    assert c.adapter.accepted == 0


def test_generation_replay_and_missing_closed_never_restore_authority(channel):
    c, peer = channel
    c.prepare_adapter(7)
    c.adapter.end_metadata_stream("CAPTURE_STOP")
    with pytest.raises(ValueError, match="GENERATION_REPLAY"):
        c.prepare_adapter(7)
    c.prepare_adapter(8)
    peer.shutdown(socket.SHUT_WR)
    with pytest.raises(ValueError, match="EOF_WITHOUT_CLOSED"):
        c.pump()
    assert c.snapshot()["state"] == "ERROR" and not c.snapshot()["automatic_restart"]


def test_consumer_shutdown_error_preserves_first_failure(channel, monkeypatch):
    c, _ = channel

    class BrokenSocket:
        def shutdown(self, _how):
            raise OSError("synthetic already-closed peer")

    def fail():
        c.error = "TCX_DATA_EOF_WITHOUT_CLOSED"
        c.transport_failed = True  # Real pump marks EOF fatal; a processing error alone must drain.
        raise ValueError(c.error)

    monkeypatch.setattr(
        "soc_agent.security_ai.ebpf_tc.data_plane.select.select", lambda *_: ([c.channel], [], [])
    )
    monkeypatch.setattr(c, "pump", fail)
    c.channel = BrokenSocket()
    c._consume()
    assert c.error == "TCX_DATA_EOF_WITHOUT_CLOSED"


def test_reader_delivers_without_any_control_request(channel):
    import threading
    import time

    c, peer = channel
    c.prepare_adapter(7)
    c.worker = threading.Thread(target=c._consume, daemon=True)
    c.worker.start()
    try:
        peer.send(frame(c))
        import struct

        end = struct.pack("<Q", 7) + bytes(24) + struct.pack("<I", 1) + bytes(44)
        peer.send(frame(c, kind=4, sequence=2, packet=end))
        peer.send(frame(c, kind=3, sequence=3, packet=bytes(80)))
        deadline = time.monotonic() + 2
        while not (c.adapter.accepted == 1 and c.closed) and time.monotonic() < deadline:
            time.sleep(0.005)
        assert c.adapter.accepted == 1 and c.sequence == 3
        assert c.adapter.flow.closed and c.closed
        assert c.snapshot()["processing"]["accepted"] == 1
        assert c.snapshot()["source"] == "ORDINARY_UID_PACKET_FIXTURE"
    finally:
        c.stop_event.set()
        c.worker.join(timeout=2)
    assert not c.worker.is_alive()


def test_selector_failure_is_not_a_silent_reader_exit(channel, monkeypatch):
    c, _ = channel

    def unavailable(*_args):
        raise OSError("synthetic selector failure")

    monkeypatch.setattr("soc_agent.security_ai.ebpf_tc.data_plane.select.select", unavailable)
    c._consume()
    assert c.error == "TCX_DATA_READER_FAILURE"
    assert c.snapshot()["state"] == "ERROR"
