"""No AF_PACKET socket. Synthetic metadata over a real ordinary-user UNIX socket."""

import asyncio
import errno
import socket
import threading
from types import SimpleNamespace

import pytest
from tests.streaming_network_support import packet

from soc_agent.security_ai.operational.network_capture import helper_transport
from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable
from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy, prepare
from soc_agent.security_ai.operational.network_capture.stream_transport import (
    StreamingCapture,
    StreamMessage,
)
from soc_agent.security_ai.research.live_input import timestamp_ns


@pytest.mark.parametrize(
    ("number", "closed", "translated"),
    [
        (errno.EBADF, True, True),
        (errno.EINVAL, True, True),
        (errno.EACCES, True, False),
        (errno.EBADF, False, False),
    ],
)
def test_listener_shutdown_translates_only_owner_closed_socket(number, closed, translated):
    stopped = threading.Event()
    original = OSError(number, "accept failure")

    def accept():
        if closed:
            stopped.set()
        raise original

    capture = SimpleNamespace(closed=stopped, listener=SimpleNamespace(accept=accept))
    if translated:
        with pytest.raises(CaptureUnavailable, match="^HELPER_LISTENER_CLOSED$") as result:
            helper_transport.HelperCapture.handshake(capture)
        assert result.value.__cause__ is original
    else:
        with pytest.raises(OSError) as result:
            helper_transport.HelperCapture.handshake(capture)
        assert result.value is original


def stat(s, seq, count, *, kind="HEARTBEAT", **extra):
    return StreamMessage(
        kind=kind,
        session_id=s.session_id,
        counter_sequence=seq,
        kernel_packets=1 if seq > 1 else 0,
        kernel_packets_total=count,
        capture_drops=0,
        capture_drops_total=0,
        counter_status="COUNTER_VERIFIED",
        **extra,
    )


def native_shaped(s, n):
    # Simulated kernel fields only; never sent to model authorizer as native evidence.
    value = packet(SimpleNamespace(session=s), n / 100)
    return value.model_copy(
        update={
            "timestamp_origin": "KERNEL_SO_TIMESTAMPNS",
            "capture_timestamp_ns": timestamp_ns(value),
        }
    )


@pytest.mark.asyncio
async def test_real_unix_transport_over_512_frames_without_capture(tmp_path, monkeypatch):
    directory = tmp_path / "session"
    s = prepare(directory, StreamPolicy(transport_capacity=512))
    capture = StreamingCapture(directory, s)
    # Explicitly mock privilege/raw-socket attestation only; no native authorization claim.
    monkeypatch.setattr(helper_transport, "validate_peer", lambda *a, **kw: None)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.settimeout(1)
    client.connect(s.socket_address)
    client.sendall(stat(s, 1, 0, kind="READY").model_dump_json().encode())
    await asyncio.to_thread(capture.handshake)
    capture.start_reader()
    errors = []

    def send():
        try:
            for n in range(1, 601):
                client.sendall(
                    stat(s, n + 1, n, received_frames=n, sent_packets=n - 1)
                    .model_dump_json()
                    .encode()
                )
                client.sendall(
                    StreamMessage(
                        kind="PACKET",
                        session_id=s.session_id,
                        counter_sequence=n + 1,
                        sequence=n,
                        packet=native_shaped(s, n),
                    )
                    .model_dump_json()
                    .encode()
                )
            client.sendall(
                StreamMessage(
                    kind="CLOSED",
                    session_id=s.session_id,
                    counter_sequence=602,
                    kernel_packets=0,
                    kernel_packets_total=600,
                    capture_drops=0,
                    capture_drops_total=0,
                    counter_status="COUNTER_VERIFIED",
                    received_frames=600,
                    sent_packets=600,
                    elapsed_seconds=6,
                )
                .model_dump_json()
                .encode()
            )
        except OSError as e:
            errors.append(type(e).__name__)

    thread = threading.Thread(target=send)
    thread.start()
    try:
        delivered = []

        async def drain():
            while capture.terminal is None or not capture.packets.empty():
                p = await asyncio.to_thread(capture.receive)
                if p is not None:
                    delivered.append(capture.last_seal)
                else:
                    await asyncio.sleep(0.001)

        await asyncio.wait_for(drain(), 10)
        assert len(delivered) == 600
        assert [x[0] for x in delivered] == list(range(1, 601))
        assert capture.completion_verified()
        assert capture.extra_metrics()["kernel_packets_total"] == 600
        assert capture.extra_metrics()["capture_drops"] == 0
        assert capture.extra_metrics()["dns9_producer_parity"] == "UNVERIFIED"
        assert not errors
        assert capture.queue_high_water <= 512
    finally:
        capture.close()
        client.close()
        thread.join(1)
    assert not capture.reader_thread.is_alive()
    assert not capture.seals


@pytest.mark.parametrize("fault", ["counter", "duplicate", "dns", "drop", "unknown"])
def test_transport_fault_rejection(tmp_path, fault):
    s = prepare(tmp_path / "session", StreamPolicy())
    capture = StreamingCapture(tmp_path / "session", s)
    try:
        capture.accept_counters(stat(s, 1, 0, kind="READY"))
        if fault == "counter":
            value = StreamMessage(
                kind="PACKET",
                session_id=s.session_id,
                sequence=1,
                counter_sequence=2,
                packet=native_shaped(s, 1),
            )
        elif fault == "duplicate":
            value = StreamMessage(
                kind="PACKET",
                session_id=s.session_id,
                sequence=2,
                counter_sequence=1,
                packet=native_shaped(s, 1),
            )
        elif fault == "dns":
            value = stat(s, 2, 1, dns_queries=4)
        else:
            value = stat(s, 2, 1).model_copy(
                update={
                    "counter_status": "CAPTURE_DROPS_DETECTED"
                    if fault == "drop"
                    else "COUNTER_UNAVAILABLE",
                    "capture_drops": 1 if fault == "drop" else None,
                    "capture_drops_total": 1 if fault == "drop" else None,
                }
            )
        with pytest.raises(CaptureUnavailable):
            capture._receive_record(value)
    finally:
        capture.close()
