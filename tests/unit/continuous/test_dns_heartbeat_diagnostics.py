"""Ordinary AF_UNIX only: no raw capture, DNS traffic, cgroup changes or API."""

import json
import os
import socket
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.unit.continuous.test_dns_source import prepared
from tests.unit.streaming_network.test_transport import native_shaped, stat

from soc_agent.continuous.dns_source import DNSCapture
from soc_agent.security_ai.operational.network_capture import helper_transport
from soc_agent.security_ai.operational.network_capture.live_helper import process_start
from soc_agent.security_ai.operational.network_capture.stream_transport import (
    StreamMessage,
    TransportTrace,
)


def trace(sequence, **changes):
    return TransportTrace(
        **(
            dict(
                sequence=sequence,
                pid=os.getpid(),
                process_start=process_start(os.getpid()),
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                time_namespace=os.readlink("/proc/self/ns/time"),
                generated_monotonic_ns=time.monotonic_ns(),
                generated_wall_ns=time.time_ns(),
            )
            | changes
        )
    )


@pytest.fixture
def transport(tmp_path, monkeypatch):
    directory, session, _ = prepared(tmp_path)
    capture = DNSCapture(directory, session)
    # Only peer privileged raw-socket attestation is simulated; actual local IPC.
    monkeypatch.setattr(helper_transport, "validate_peer", lambda *a, **kw: None)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.connect(session.socket_address)
    client.sendall(
        stat(
            session,
            1,
            0,
            kind="READY",
            pid=os.getpid(),
            process_start=process_start(os.getpid()),
            transport_trace=trace(1),
        )
        .model_dump_json()
        .encode()
    )
    capture.handshake()
    try:
        yield capture, client, session
    finally:
        if isinstance(capture.reader_thread, SimpleNamespace):
            capture.reader_thread = None
        capture.close()
        client.close()


def descheduled_reader(capture):
    # A present reader that has not been scheduled yet; no heartbeat deadline change.
    capture.reader_thread = SimpleNamespace(join=lambda _: None, is_alive=lambda: True)
    capture.last_heartbeat = time.monotonic() - 3


def test_cached_stale_consumer_validates_already_queued_heartbeat(transport):
    capture, client, session = transport
    descheduled_reader(capture)
    client.sendall(stat(session, 2, 1, transport_trace=trace(2)).model_dump_json().encode())
    assert capture.statistics() == (1, 0)
    assert time.monotonic() - capture.last_heartbeat < 2
    assert capture.trace_sequence == 2
    assert capture.sequence == capture.delivered == 0
    assert capture.reader_error is None and capture.terminal is None
    assert not capture.completion_verified()


def test_reader_rechecks_ipc_after_descheduling_between_empty_poll_and_deadline(transport):
    capture, client, session = transport
    # Model the real Reader's select timeout returning before descheduling:
    # authenticated control arrives before check_reader_liveness finally runs.
    capture.last_heartbeat = time.monotonic() - 3
    client.sendall(stat(session, 2, 1, transport_trace=trace(2)).model_dump_json().encode())
    capture.check_reader_liveness()
    assert capture.trace_sequence == 2 and capture.reader_error is None
    assert capture.delivered == 0 and not capture.completion_verified()


def test_empty_ipc_still_fails_unchanged_two_second_bound(transport):
    capture, _, _ = transport
    descheduled_reader(capture)
    with pytest.raises(ValueError, match="HELPER_HEARTBEAT_OR_PROCESS_STALE"):
        capture.statistics()


def test_consumer_control_drain_preserves_packet_queue_and_seal_accounting(transport):
    capture, client, session = transport
    descheduled_reader(capture)
    client.sendall(stat(session, 2, 1, transport_trace=trace(2)).model_dump_json().encode())
    client.sendall(
        StreamMessage(
            kind="PACKET",
            session_id=session.session_id,
            sequence=1,
            counter_sequence=2,
            packet=native_shaped(session, 1),
            transport_trace=trace(3),
        )
        .model_dump_json()
        .encode()
    )
    assert capture.statistics() == (1, 0)
    assert capture.delivered == 0 and capture.packets.qsize() == len(capture.seals) == 1
    assert capture.receive() is not None
    assert capture.delivered == 1 and capture.packets.empty() and not capture.seals
    assert capture.last_seal == (1, 2)
    assert not capture.completion_verified()


def test_control_reception_is_bounded_even_with_long_backlog(transport):
    capture, client, session = transport
    descheduled_reader(capture)
    for sequence in range(2, 72):
        client.sendall(
            stat(session, sequence, sequence - 1, transport_trace=trace(sequence))
            .model_dump_json()
            .encode()
        )
    assert capture.statistics() == (64, 0)
    assert capture.trace_sequence == 65
    assert capture.ipc_diagnostics()["available_bytes"] > 0
    assert capture.delivered == 0 and capture.terminal is None


def test_queued_closed_is_not_reclassified_stale_by_reader(transport):
    capture, client, session = transport
    descheduled_reader(capture)
    client.sendall(
        stat(
            session,
            2,
            1,
            kind="CLOSED",
            elapsed_seconds=1,
            received_frames=1,
            sent_packets=0,
            transport_trace=trace(2),
        )
        .model_dump_json()
        .encode()
    )
    assert capture.statistics() == (1, 0)
    capture.last_heartbeat = time.monotonic() - 30
    capture._read_loop()
    assert capture.reader_error is None and capture.completion_verified()


def test_backlog_identity_violation_is_never_rescued(transport):
    capture, client, session = transport
    descheduled_reader(capture)
    invalid = trace(2, process_start="123")
    client.sendall(stat(session, 2, 1, transport_trace=invalid).model_dump_json().encode())
    with pytest.raises(ValueError, match="HELPER_TRANSPORT_TRACE_INVALID"):
        capture.statistics()
    assert capture.trace_sequence == 1 and capture.counter_sequence == 1


@pytest.mark.parametrize(
    "change",
    [
        {"sequence": 3},
        {"boot_id": "0" * 36},
        {"time_namespace": "time:[99999]"},
        {"generated_monotonic_ns": 2**63},
        {"previous_send_started_ns": 100, "previous_send_completed_ns": 99},
    ],
)
def test_trace_replay_clock_domain_and_send_order_fail_closed(transport, change):
    capture, _, session = transport
    values = trace(2).model_dump() | change
    message = stat(session, 2, 1, transport_trace=TransportTrace(**values))
    with pytest.raises(ValueError, match="HELPER_TRANSPORT_TRACE_INVALID"):
        capture._receive_record(message)
    assert capture.counter_sequence == 1


def test_delayed_send_and_receive_are_separate_monotonic_intervals(transport):
    capture, _, session = transport
    now = time.monotonic_ns()
    previous_generated = capture.last_transport_trace["generated_monotonic_ns"]
    message = stat(
        session,
        2,
        1,
        transport_trace=trace(
            2,
            generated_monotonic_ns=max(previous_generated, now - 1_000_000),
            previous_send_started_ns=now - 4_000_000,
            previous_send_completed_ns=now - 2_000_000,
        ),
    )
    capture._receive_record(message)
    value = capture.extra_metrics()
    t = value["transport_trace"]
    assert t["same_boot_clock"] and t["generate_to_receive_ns"] >= 0
    assert t["previous_send_completed_ns"] - t["previous_send_started_ns"] == 2_000_000
    assert t["send_completion_scope"].startswith("PREVIOUS_RECORD_ONLY")
    assert value["snapshot_observed_monotonic_ns"] >= t["received_monotonic_ns"]
    assert "payload" not in json.dumps(t).lower()


def test_local_ipc_backpressure_is_observable_without_payload(transport):
    capture, client, _ = transport
    before = capture.ipc_diagnostics()
    client.setblocking(False)
    sent = 0
    with pytest.raises(BlockingIOError):
        while sent < 10000:
            client.send(b"x" * 1000)
            sent += 1
    result = capture.ipc_diagnostics()
    assert before["available_bytes"] == 0 and result["available_bytes"] == sent * 1000
    assert sent > 0 and result["receive_buffer"] > 0
    assert result["scope"].endswith("NOT_RECORD_COUNT")
    assert "x" * 20 not in json.dumps(result)


def test_process_identity_cpu_and_throttling_are_diagnostic_only(transport):
    capture, _, _ = transport
    before = capture.process_diagnostics()
    assert before["pid"] == os.getpid() and before["state"] not in ("UNKNOWN", "IDENTITY_CHANGED")
    if "cpu_stat" in before:
        assert before["cpu_stat"]["nr_throttled"] >= 0
        assert before["cpu_stat"]["throttled_usec"] >= 0
    # Counter unavailability cannot become a false process-exit/cleanup receipt.
    capture.ready = capture.ready.model_copy(update={"process_start": "1"})
    assert capture.process_diagnostics()["state"] == "IDENTITY_CHANGED"
    assert not capture.completion_verified()


def test_simulated_cpu_quota_throttling_delta_is_not_process_exit(transport, monkeypatch):
    capture, _, _ = transport
    original = Path.read_text
    values = iter(
        [
            "usage_usec 100\nnr_throttled 1\nthrottled_usec 50\n",
            "usage_usec 200\nnr_throttled 9\nthrottled_usec 700050\n",
        ]
    )

    def counters(path, *args, **kwargs):
        if path.name == "cpu.stat":
            return next(values)
        if path.name == "cpu.max":
            return "10000 100000\n"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counters)
    first, second = capture.process_diagnostics(), capture.process_diagnostics()
    assert second["cpu_stat"]["nr_throttled"] - first["cpu_stat"]["nr_throttled"] == 8
    assert second["cpu_stat"]["throttled_usec"] - first["cpu_stat"]["throttled_usec"] == 700000
    assert second["cpu_max"] == "10000 100000"
    assert second["state"] == first["state"] and not capture.completion_verified()


def test_reader_failure_persists_identity_backlog_and_trace_without_success(transport):
    capture, _, _ = transport
    descheduled_reader(capture)
    capture.reader_last_poll = time.monotonic() - 3.5
    capture._read_loop()
    value = json.loads((capture.directory / "transport-failure.json").read_text())
    assert value["heartbeat_deadline_seconds"] == 2
    assert value["reader_max_poll_gap_seconds"] >= 3.5
    assert value["transport_trace"]["sequence"] == 1
    assert value["last_successful_receive_monotonic_ns"] is not None
    assert value["process_at_failure"]["pid"] == os.getpid()
    assert value["ipc_at_failure"]["available_bytes"] == 0
    assert not capture.cleanup_ack_verified() and not capture.completion_verified()
