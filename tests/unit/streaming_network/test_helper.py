"""Every privilege, signal, capture and transport effect is mocked in-process."""

import json
import socket
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.unit.live_network.test_counters import MockSocket, encoded
from tests.unit.network_capture.test_packets import frame

from soc_agent.security_ai.operational.network_capture import stream_helper as helper
from soc_agent.security_ai.operational.network_capture.capture import PacketCapture
from soc_agent.security_ai.research.models import digest


@pytest.mark.parametrize(
    "case",
    [
        "normal",
        "unknown",
        "drop",
        "send_timeout",
        "stop",
        "rate",
        "deadline",
        "disconnect",
        "closed_send_failure",
        "loopback_regression",
        "raw_burst",
    ],
)
def test_mock_helper_lifecycle_fail_closed(monkeypatch, tmp_path, case):
    messages = []
    controls = []
    streams = []
    session = SimpleNamespace(
        interface="lo",
        interface_id="a" * 64,
        seconds=300,
        max_packets=38656 if case == "raw_burst" else 4 if case == "loopback_regression" else 1,
        socket_address="MOCK_ONLY",
        session_id=uuid4(),
        policy=SimpleNamespace(
            helper_cpu_seconds=35, frames_per_second=128, burst_frames=256, dns_headers=True
        ),
    )
    session.model_dump = lambda **kwargs: {"mock_session": True}
    approval = digest(session.model_dump())
    samples = [encoded(0, 0), encoded(1, 0), encoded(0, 0)]
    if case == "loopback_regression":
        samples = [encoded(0, 0), *(encoded(1, 0) for _ in range(4)), encoded(0, 0)]
    if case == "raw_burst":
        samples = [encoded(0, 0), *(encoded(1, 0) for _ in range(257))]
    if case == "unknown":
        samples[1] = OSError("private")
    if case == "drop":
        samples[1] = encoded(1, 1)

    class Capture(PacketCapture):
        def __init__(self, config):
            super().__init__(config)
            self.raw = MockSocket(samples)
            streams.append(self)

        def open(self):
            self.socket = self.raw

        def receive(self):
            if case == "loopback_regression":
                index = getattr(self, "received", 0)
                self.received = index + 1
                seconds = 1800000002 if index < 2 else 1800000001
                return (
                    frame(),
                    datetime.fromtimestamp(seconds, UTC),
                    ("OUTBOUND" if index % 2 == 0 else "INBOUND"),
                    seconds * 10**9,
                )
            now = datetime.now(UTC)
            return (
                frame(),
                now,
                "INBOUND" if case == "raw_burst" else "OUTBOUND",
                int(now.timestamp()) * 10**9 + now.microsecond * 1000,
            )

    class Channel:
        def __init__(self, *args):
            assert args == (socket.AF_UNIX, socket.SOCK_SEQPACKET)

        def settimeout(self, value):
            assert value == 0.5

        def connect(self, value):
            assert value == "MOCK_ONLY"

        def sendall(self, body):
            message = json.loads(body)
            if case == "closed_send_failure" and message["kind"] == "CLOSED":
                raise BrokenPipeError("MOCK_CONTROLLER_DISCONNECT")
            if case == "send_timeout" and message["kind"] == "PACKET":
                raise TimeoutError()
            messages.append(message)

        def recv(self, _):
            return b"" if case == "disconnect" else b"STOP"

        def close(self):
            controls.append("CHANNEL_CLOSED")

    monkeypatch.setattr(helper, "check_privileges", lambda: controls.append("CHECK_MOCK"))
    monkeypatch.setattr(helper, "drop_privileges", lambda: controls.append("DROP_MOCK"))
    monkeypatch.setattr(helper, "load", lambda _: session)
    monkeypatch.setattr(helper, "PacketCapture", Capture)
    monkeypatch.setattr(helper, "interface_identity", lambda _: "a" * 64)
    monkeypatch.setattr(helper.socket, "socket", Channel)
    monkeypatch.setattr(helper.os, "readlink", lambda _: "socket:[12345]")
    monkeypatch.setattr(helper.resource, "setrlimit", lambda *a: None)
    monkeypatch.setattr(helper.signal, "signal", lambda *a: None)
    monkeypatch.setattr(helper.signal, "setitimer", lambda *a: None)
    monkeypatch.setattr(helper, "privileges", lambda: {"CapEff": 0})
    monkeypatch.setattr(
        helper.select,
        "select",
        lambda readers, *a: (
            [readers[1] if case in ("stop", "disconnect") else readers[0]],
            [],
            [],
        ),
    )
    if case == "deadline":
        clock = iter((0, 0, 299, 299))
        monkeypatch.setattr(helper, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    if case == "raw_burst":
        monkeypatch.setattr(helper, "time", SimpleNamespace(monotonic=lambda: 0.0))
    if case == "rate":

        def exceeded(*a):
            raise ValueError("STREAM_RATE_BUDGET_EXCEEDED")

        monkeypatch.setattr(helper.RateBudget, "consume", exceeded)
    if case in (
        "normal",
        "stop",
        "disconnect",
        "deadline",
        "closed_send_failure",
        "loopback_regression",
    ):
        helper.run(tmp_path, approval)
    else:
        with pytest.raises((ValueError, OSError)):
            helper.run(tmp_path, approval)
    assert messages[0]["kind"] == "READY"
    if case == "closed_send_failure":
        # Existing approved helper returns normally even if final send fails.
        assert not any(m["kind"] == "CLOSED" for m in messages)
    else:
        assert messages[-1]["kind"] == "CLOSED"
    assert streams[0].raw.closed
    assert controls == ["CHECK_MOCK", "DROP_MOCK", "CHANNEL_CLOSED"]
    if case == "normal":
        assert [m["kind"] for m in messages] == ["READY", "HEARTBEAT", "PACKET", "CLOSED"]
        assert messages[2]["counter_sequence"] == 2
        assert messages[2]["packet"]["dns"] is None
    if case == "loopback_regression":
        packets = [m for m in messages if m["kind"] == "PACKET"]
        assert [m["sequence"] for m in packets] == [1, 2]
        assert [m["packet"]["direction"] for m in packets] == ["OUTBOUND", "OUTBOUND"]
        assert [m["packet"]["capture_timestamp_ns"] for m in packets] == [
            1800000002 * 10**9,
            1800000001 * 10**9,
        ]
        assert messages[-1]["received_frames"] == 4 and messages[-1]["sent_packets"] == 2
    if case in ("unknown", "drop", "rate", "stop", "disconnect", "deadline"):
        assert not any(m["kind"] == "PACKET" for m in messages)
    if case == "rate":
        # The approved helper already sends its explicit error and final counters.
        assert messages[-1]["error"] == "STREAM_RATE_BUDGET_EXCEEDED"
        assert messages[-1]["received_frames"] == 1
        assert messages[-1]["sent_packets"] == 0
        assert messages[-1]["counter_sequence"] == 2
        assert messages[-1]["counter_status"] == "COUNTER_VERIFIED"
    if case == "raw_burst":
        # 257 raw inbound clones exhaust the real bucket without forwarding any packet.
        assert [m["kind"] for m in messages] == ["READY", *(["HEARTBEAT"] * 256), "CLOSED"]
        assert messages[-1]["error"] == "STREAM_RATE_BUDGET_EXCEEDED"
        assert messages[-1]["received_frames"] == 257
        assert messages[-1]["sent_packets"] == 0
        assert messages[-1]["kernel_packets_total"] == 257
    assert "private" not in str(messages)


def test_unprivileged_new_helper_rejects_before_socket_open(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(helper, "PacketCapture", lambda *a: calls.append(a))
    with pytest.raises(ValueError, match="ONLY_TEMPORARY_CAP_NET_RAW"):
        helper.run(tmp_path / "not-a-session", "a" * 64)
    assert not calls


def test_session_scope_digest_rejected_before_constructing_capture(monkeypatch, tmp_path):
    calls = []
    session = SimpleNamespace(model_dump=lambda **kwargs: {"policy": {"seconds": 1800}})
    monkeypatch.setattr(helper, "check_privileges", lambda: None)
    monkeypatch.setattr(helper, "load", lambda _: session)
    monkeypatch.setattr(helper, "PacketCapture", lambda *a: calls.append(a))
    with pytest.raises(ValueError, match="APPROVED_SESSION_DIGEST_MISMATCH"):
        helper.run(tmp_path, digest({"policy": {"seconds": 300}}))
    assert not calls
