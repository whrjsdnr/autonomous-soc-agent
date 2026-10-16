"""Counter and helper control flow with mock sockets only. No capabilities or capture."""

import errno
import json
import socket
import struct
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.unit.network_capture.test_packets import frame

from soc_agent.security_ai.operational.network_capture import live_helper as helper
from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    PacketCapture,
)
from soc_agent.security_ai.operational.network_capture.helper_transport import (
    HelperCapture,
    Message,
)
from soc_agent.security_ai.operational.network_capture.live_session import prepare
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig


def encoded(packets, drops):
    return struct.pack("=II", packets, drops)


class MockSocket:
    def __init__(self, samples):
        self.samples = iter(samples)
        self.closed = False
        self.calls = 0

    def getsockopt(self, *args):
        assert args == (263, 6, 12)
        self.calls += 1
        if self.closed:
            raise OSError(errno.EBADF, "private error text must not be retained")
        value = next(self.samples)
        if isinstance(value, Exception):
            raise value
        return value

    def close(self):
        self.closed = True

    def fileno(self):
        return 123


def capture_for(samples):
    capture = PacketCapture(CaptureConfig(interface="lo"))
    capture.socket = MockSocket(samples)
    return capture


@pytest.mark.parametrize("length", [0, 1, 4, 7, 9, 10, 11, 13])
def test_statistics_rejects_invalid_return_length(length):
    capture = capture_for([b"\0" * length])
    assert capture.statistics() is None
    assert capture.statistics_error == "INVALID_STATISTICS_LENGTH"


@pytest.mark.parametrize("suffix", [b"", b"\0" * 4])
def test_statistics_accepts_both_linux_layout_lengths(suffix):
    capture = capture_for([encoded(7, 2) + suffix])
    assert capture.statistics() == (7, 2)
    assert capture.statistics_error is None


@pytest.mark.parametrize("number", [errno.EBADF, errno.ENOPROTOOPT, errno.EIO])
def test_oserror_is_unknown_not_zero_and_details_are_sanitized(number):
    capture = capture_for([OSError(number, "do not expose this path or credential")])
    assert capture.statistics() is None
    assert capture.statistics_error == "GETSOCKOPT_FAILED_ERRNO_" + str(number)


def test_closed_socket_and_not_open_are_separate_causes():
    capture = capture_for([])
    stream = capture.socket
    stream.close()
    assert capture.statistics() is None
    assert capture.statistics_error == "GETSOCKOPT_FAILED_ERRNO_9"
    capture.close()
    assert capture.statistics() is None
    assert capture.statistics_error == "SOCKET_NOT_OPEN"


def test_reset_intervals_add_once_not_cumulative_on_the_wire():
    capture = capture_for([encoded(7, 0), encoded(3, 0), encoded(0, 0)])
    tracker = helper.CaptureCounters(capture)
    messages = [tracker.sample() for _ in range(3)]
    assert [m["kernel_packets"] for m in messages] == [7, 3, 0]
    assert [m["kernel_packets_total"] for m in messages] == [7, 10, 10]
    assert [m["counter_sequence"] for m in messages] == [1, 2, 3]
    assert all(m["counter_status"] == "COUNTER_VERIFIED" for m in messages)


@pytest.mark.parametrize("bad", [OSError(errno.EIO, "secret"), b"", encoded(2, 1), encoded(1, 2)])
def test_failed_interval_is_sticky_after_kernel_reset(bad):
    tracker = helper.CaptureCounters(capture_for([bad, encoded(0, 0)]))
    first, last = tracker.sample(), tracker.sample()
    expected = "CAPTURE_DROPS_DETECTED" if bad == encoded(2, 1) else "COUNTER_UNAVAILABLE"
    assert first["counter_status"] == last["counter_status"] == expected
    with pytest.raises(ValueError, match="HELPER_CAPTURE_"):
        helper.require_counters(last)
    if expected == "CAPTURE_DROPS_DETECTED":
        assert last["capture_drops"] == 0 and last["capture_drops_total"] == 1
    else:
        assert last["capture_drops_total"] is None
        assert last["kernel_packets_total"] is None


@pytest.fixture
def simulated_helper(monkeypatch):
    """Run pure helper logic with every OS-effect boundary replaced; no helper process."""
    streams, channels, controls = [], [], []
    behavior = {"mode": "packet", "fail_send": None}
    session = SimpleNamespace(
        interface="lo",
        interface_id="a" * 64,
        seconds=60,
        max_packets=1,
        socket_address="MOCK_ONLY",
        session_id=uuid4(),
    )

    class Capture(PacketCapture):
        def __init__(self, config):
            super().__init__(config)
            self.raw = MockSocket(behavior["samples"])
            streams.append(self)

        def open(self):
            self.socket = self.raw

        def receive(self):
            stamp = datetime.now(UTC)
            return (
                frame(),
                stamp,
                "OUTBOUND",
                int(stamp.timestamp()) * 10**9 + stamp.microsecond * 1000,
            )

    class Channel:
        def __init__(self, *args):
            assert args == (socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self.messages = []
            self.closed = False
            channels.append(self)

        def settimeout(self, seconds):
            assert seconds == 0.5

        def connect(self, address):
            assert address == "MOCK_ONLY"

        def sendall(self, body):
            value = json.loads(body)
            if value["kind"] == behavior["fail_send"]:
                behavior["fail_send"] = None
                raise TimeoutError("simulated backpressure")
            self.messages.append(value)

        def recv(self, size):
            return b"STOP"

        def close(self):
            self.closed = True

    def select(readers, *args):
        if behavior["mode"] == "watchdog":
            raise ValueError("HELPER_WATCHDOG_EXPIRED")
        return ([readers[1]] if behavior["mode"] == "stop" else [readers[0]], [], [])

    monkeypatch.setattr(helper, "check_privileges", lambda: controls.append("MOCK_CHECK_ONLY"))
    monkeypatch.setattr(helper, "drop_privileges", lambda: controls.append("MOCK_DROP_ONLY"))
    monkeypatch.setattr(helper, "load_session", lambda p: session)
    monkeypatch.setattr(helper, "interface_identity", lambda i: session.interface_id)
    monkeypatch.setattr(helper, "PacketCapture", Capture)
    monkeypatch.setattr(helper.socket, "socket", Channel)
    monkeypatch.setattr(helper.os, "readlink", lambda p: "socket:[12345]")
    monkeypatch.setattr(helper.resource, "setrlimit", lambda *a: None)
    monkeypatch.setattr(helper.signal, "signal", lambda *a: None)
    monkeypatch.setattr(helper.signal, "setitimer", lambda *a: None)
    monkeypatch.setattr(helper.select, "select", select)
    monkeypatch.setattr(helper, "privileges", lambda: {"CapEff": 0})
    return behavior, streams, channels, controls, session


def test_helper_ready_heartbeat_packet_closed_order_and_final_query(simulated_helper, tmp_path):
    behavior, streams, channels, controls, _ = simulated_helper
    behavior["samples"] = [encoded(2, 0), encoded(3, 0), encoded(1, 0)]
    helper.run(tmp_path)
    messages = channels[0].messages
    assert [m["kind"] for m in messages] == ["READY", "HEARTBEAT", "PACKET", "CLOSED"]
    stats = [m for m in messages if m["kind"] != "PACKET"]
    assert [m["counter_sequence"] for m in stats] == [1, 2, 3]
    assert [m["kernel_packets_total"] for m in stats] == [2, 5, 6]
    assert messages[-1]["error"] is None
    assert streams[0].raw.calls == 3 and streams[0].raw.closed and channels[0].closed
    assert controls == ["MOCK_CHECK_ONLY", "MOCK_DROP_ONLY"]


@pytest.mark.parametrize("phase", ["ready", "heartbeat", "closed"])
@pytest.mark.parametrize("failure", ["unknown", "drop"])
def test_helper_classifies_failures_at_all_phases(simulated_helper, tmp_path, phase, failure):
    behavior, streams, channels, _, _ = simulated_helper
    bad = OSError(errno.EIO, "private") if failure == "unknown" else encoded(2, 1)
    samples = [encoded(0, 0)] * 3
    samples[["ready", "heartbeat", "closed"].index(phase)] = bad
    behavior["samples"] = samples
    expected = (
        "HELPER_CAPTURE_COUNTER_UNAVAILABLE"
        if failure == "unknown"
        else "HELPER_CAPTURE_DROPS_DETECTED"
    )
    with pytest.raises(ValueError, match=expected):
        helper.run(tmp_path)
    messages = channels[0].messages
    assert messages[-1]["kind"] == "CLOSED" and messages[-1]["error"] == expected
    assert "private" not in json.dumps(messages)
    if phase in ("ready", "heartbeat"):
        assert not any(m["kind"] == "PACKET" for m in messages)
    assert streams[0].raw.closed and channels[0].closed


@pytest.mark.parametrize("mode", ["stop", "watchdog"])
def test_stop_and_watchdog_preserve_final_counter_query(simulated_helper, tmp_path, mode):
    behavior, streams, channels, _, _ = simulated_helper
    behavior.update(mode=mode, samples=[encoded(0, 0), encoded(1, 0)])
    if mode == "watchdog":
        with pytest.raises(ValueError, match="WATCHDOG_EXPIRED"):
            helper.run(tmp_path)
    else:
        helper.run(tmp_path)
    closed = channels[0].messages[-1]
    assert closed["kind"] == "CLOSED" and closed["counter_sequence"] == 2
    assert closed["kernel_packets_total"] == 1
    assert streams[0].raw.calls == 2 and streams[0].raw.closed
    assert not any(m["kind"] == "PACKET" for m in channels[0].messages)


@pytest.mark.parametrize("kind", ["HEARTBEAT", "PACKET"])
def test_backpressure_does_not_retry_and_closes_capture(simulated_helper, tmp_path, kind):
    behavior, streams, channels, _, _ = simulated_helper
    behavior.update(fail_send=kind, samples=[encoded(0, 0), encoded(1, 0), encoded(0, 0)])
    with pytest.raises(TimeoutError):
        helper.run(tmp_path)
    closed = channels[0].messages[-1]
    assert closed["kind"] == "CLOSED" and closed["error"] == "HELPER_TRANSPORT_TIMEOUT"
    assert streams[0].raw.closed and channels[0].closed
    assert streams[0].raw.calls == 3


def stat_message(session, sequence, packets, total, **overrides):
    values = dict(
        kind="HEARTBEAT",
        session_id=session.session_id,
        counter_sequence=sequence,
        kernel_packets=packets,
        kernel_packets_total=total,
        capture_drops=0,
        capture_drops_total=0,
        counter_status="COUNTER_VERIFIED",
    )
    values.update(overrides)
    return Message(**values)


@pytest.fixture
def receiver(tmp_path):
    session = prepare(tmp_path / "session")
    capture = HelperCapture(tmp_path / "session", session)
    capture.last_heartbeat = time.monotonic()
    try:
        yield capture, session
    finally:
        capture.close()


def test_transport_sums_reset_deltas_without_double_count(receiver):
    capture, s = receiver
    capture.accept_counters(stat_message(s, 1, 7, 7, kind="READY"))
    assert capture.statistics() == (7, 0)
    assert capture.statistics() == (0, 0)
    capture.accept_counters(stat_message(s, 2, 3, 10))
    capture.accept_counters(stat_message(s, 3, 0, 10, kind="CLOSED"))
    assert capture.statistics() == (3, 0)
    assert capture.counter_totals == [10, 0]


@pytest.mark.parametrize(
    "case", ["duplicate", "missing", "wrong_total", "unknown", "drop", "old_protocol"]
)
def test_transport_fail_closed_on_counter_fault(receiver, case):
    capture, s = receiver
    capture.accept_counters(stat_message(s, 1, 2, 2, kind="READY"))
    message = stat_message(s, 2, 3, 5)
    updates = {
        "duplicate": {"counter_sequence": 1},
        "missing": {"counter_sequence": 3},
        "wrong_total": {"kernel_packets_total": 99},
        "unknown": {
            "counter_status": "COUNTER_UNAVAILABLE",
            "kernel_packets": None,
            "kernel_packets_total": None,
        },
        "drop": {
            "counter_status": "CAPTURE_DROPS_DETECTED",
            "capture_drops": 1,
            "capture_drops_total": 1,
        },
        "old_protocol": {
            "counter_sequence": None,
            "counter_status": None,
            "kernel_packets_total": None,
        },
    }
    message = message.model_copy(update=updates[case])
    expected = (
        "DROPS_DETECTED"
        if case == "drop"
        else "COUNTER_UNAVAILABLE"
        if case == "unknown"
        else "COUNTER_INTEGRITY_FAILED"
    )
    with pytest.raises(CaptureUnavailable, match=expected):
        capture.accept_counters(message)
    with pytest.raises(CaptureUnavailable, match=expected):
        capture.statistics()  # Cannot expose previously pending good deltas after failure.
    assert not capture.is_live()


def test_failed_closed_receipt_is_not_written_as_success(receiver, monkeypatch):
    capture, s = receiver
    capture.accept_counters(stat_message(s, 1, 0, 0, kind="READY"))
    capture.alive = True
    message = stat_message(
        s,
        2,
        2,
        2,
        kind="CLOSED",
        capture_drops=1,
        capture_drops_total=1,
        counter_status="CAPTURE_DROPS_DETECTED",
    )
    monkeypatch.setattr(capture, "message", lambda: message)
    with pytest.raises(CaptureUnavailable, match="DROPS_DETECTED"):
        capture.receive()
    assert not (capture.directory / "verified-closed.json").exists()
    evidence = json.loads((capture.directory / "counter-failure.json").read_text())
    assert evidence["capture_drops"] == 1 and evidence["error"] == "HELPER_CAPTURE_DROPS_DETECTED"
    assert (capture.directory / "counter-failure.json").stat().st_mode & 0o777 == 0o600


def test_zero_packet_session_is_verified_counter_not_unknown(simulated_helper, tmp_path):
    behavior, _, channels, _, _ = simulated_helper
    behavior.update(mode="stop", samples=[encoded(0, 0), encoded(0, 0)])
    helper.run(tmp_path)
    assert all(m["counter_status"] == "COUNTER_VERIFIED" for m in channels[0].messages)
    assert channels[0].messages[-1]["kernel_packets_total"] == 0


def test_missing_heartbeat_does_not_report_zero_as_current_measurement(receiver):
    capture, s = receiver
    capture.accept_counters(stat_message(s, 1, 0, 0, kind="READY"))
    capture.alive = True
    capture.last_heartbeat = time.monotonic() - 3
    with pytest.raises(CaptureUnavailable, match="HEARTBEAT_OR_PROCESS_STALE"):
        capture.statistics()


def test_native_authorization_rejects_sticky_counter_fault_before_inference(tmp_path):
    from soc_agent.security_ai.research.live_service import LiveMonitoring

    service = LiveMonitoring(tmp_path)
    service.capture = SimpleNamespace(
        ready=object(), counter_issue={"error": "HELPER_CAPTURE_COUNTER_UNAVAILABLE"}
    )
    with pytest.raises(ValueError, match="LIVE_AUTHENTICATED_SOURCE_REQUIRED"):
        service.validate_native_source(SimpleNamespace())
