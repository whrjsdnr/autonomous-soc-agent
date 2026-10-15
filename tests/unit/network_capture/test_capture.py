"""Kernel socket contract simulated without requesting capture permission."""

import socket
import struct
from datetime import UTC, datetime

import pytest
from tests.unit.network_capture.test_packets import IDENTITY, frame

from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    PacketCapture,
)
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet


class SocketFixture:
    def __init__(self):
        self.closed = False
        self.flags = 0
        self.control = [(socket.SOL_SOCKET, 35, struct.pack("@ll", 1800000000, 123456789))]
        self.address = ("lo", 0x800, 4, 1, b"")

    def recvmsg(self, *args):
        return frame(), self.control, self.flags, self.address

    def getsockopt(self, *args):
        return struct.pack("II", 7, 2)

    def close(self):
        self.closed = True


def test_kernel_clock_preserves_nanoseconds_and_direction():
    capture = PacketCapture(CaptureConfig(interface="lo"))
    capture.socket = SocketFixture()
    data, stamp, direction, nanos = capture.receive()
    value = parse_packet(
        data,
        interface_id=IDENTITY,
        timestamp=stamp,
        direction=direction,
        native=True,
        capture_timestamp_ns=nanos,
    )
    assert direction == "OUTBOUND" and value.capture_timestamp_ns == 1800000000123456789
    assert value.timestamp == datetime.fromtimestamp(1800000000, UTC).replace(microsecond=123456)
    assert capture.statistics() == (7, 2)
    stream = capture.socket
    capture.close()
    assert stream.closed


@pytest.mark.parametrize("bad", ["truncated", "missing_clock", "wrong_interface", "bad_clock"])
def test_unknown_or_truncated_kernel_records_fail_closed(bad):
    capture = PacketCapture(CaptureConfig(interface="lo"))
    capture.socket = SocketFixture()
    if bad == "truncated":
        capture.socket.flags = socket.MSG_TRUNC
    if bad == "missing_clock":
        capture.socket.control = []
    if bad == "wrong_interface":
        capture.socket.address = ("wrong0", 0, 4, 1, b"")
    if bad == "bad_clock":
        capture.socket.control = [(socket.SOL_SOCKET, 35, struct.pack("@ll", 1, 10**9))]
    with pytest.raises(CaptureUnavailable):
        capture.receive()


def test_no_native_source_claim_without_kernel_clock():
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="CLOCK"):
        parse_packet(
            frame(),
            interface_id=IDENTITY,
            timestamp=datetime.now(UTC),
            direction="INBOUND",
            native=True,
        )


def test_invalid_interface_is_not_adopted():
    with pytest.raises(CaptureUnavailable, match="INTERFACE"):
        PacketCapture(CaptureConfig(interface="not-real0"))


@pytest.mark.parametrize("phase", ["before_open", "after_bind"])
def test_interface_replacement_during_open_is_rejected(monkeypatch, phase):
    from soc_agent.security_ai.operational.network_capture import capture as module

    calls = []

    class Stream(SocketFixture):
        def bind(self, address):
            calls.append("bind")

        def setsockopt(self, *args):
            pass

        def setblocking(self, value):
            pass

    stream = Stream()
    identities = iter(
        [IDENTITY, "b" * 64] if phase == "before_open" else [IDENTITY, IDENTITY, "b" * 64]
    )
    monkeypatch.setattr(module, "interface_identity", lambda name: next(identities))

    def socket_factory(*args):
        calls.append("socket")
        return stream

    monkeypatch.setattr(module.socket, "socket", socket_factory)
    capture = PacketCapture(CaptureConfig(interface="lo"))
    with pytest.raises(CaptureUnavailable, match="INTERFACE_CHANGED"):
        capture.open()
    assert capture.socket is None
    if phase == "before_open":
        assert not calls
    else:
        assert calls == ["socket", "bind"] and stream.closed


def test_open_cannot_overwrite_an_existing_capture():
    capture = PacketCapture(CaptureConfig(interface="lo"))
    stream = SocketFixture()
    capture.socket = stream
    with pytest.raises(CaptureUnavailable, match="ALREADY_OPEN"):
        capture.open()
    assert capture.socket is stream and not stream.closed
    capture.close()
