"""Actual ordinary-user Unix IPC only; no AF_PACKET/capability/helper execution."""

import json
import threading
import time
from datetime import UTC, datetime

import pytest
from tests.live_network_performance import fixture_packets, messages
from tests.live_transport_diagnostics import fixture_channel, run_case

from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable
from soc_agent.security_ai.operational.network_capture.helper_transport import Message
from soc_agent.security_ai.research.live_service import LiveMonitoring


def wait_for(predicate):
    deadline = time.monotonic() + 2
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("FIXTURE_STATE_NOT_REACHED")
        time.sleep(0.002)


def send(sender, record):
    sender.sendall(record.model_dump_json(exclude_none=True).encode())


@pytest.mark.parametrize("separated", [False, True])
def test_full_unix_buffer_and_paused_processor_reproduces_timeout_or_drains(tmp_path, separated):
    result = run_case(tmp_path / "session", separated=separated, pause=0.65, count=48, delay=0)
    if separated:
        assert result["sender_errors"] == [] and result["closed_receipt"]
        assert result["delivered_packets"] == 48 and result["counter_totals"] == [48, 0]
        assert 1 <= result["queue_high_water"] <= 512
        assert result["duplicate_deliveries"] == 0 and result["fixture_packet_order_preserved"]
    else:
        assert result["sender_errors"] == ["SEND_TIMEOUT"]
        assert result["delivered_packets"] < 48 and not result["closed_receipt"]


def test_overflow_explicitly_rejects_and_accounts_for_unadmitted_metadata(tmp_path):
    capture, sender, s = fixture_channel(tmp_path / "session", capacity=2, separated=True)
    try:
        _, records = messages(s, fixture_packets(3, s.interface_id, datetime.now(UTC)))
        for record in list(records)[:-1]:
            send(sender, record)
        wait_for(lambda: capture.reader_error is not None)
        assert capture.reader_error == "HELPER_TRANSPORT_BACKPRESSURE"
        assert capture.packets.qsize() == 2
        with pytest.raises(CaptureUnavailable, match="BACKPRESSURE"):
            capture.receive()
        value = json.loads((capture.directory / "transport-failure.json").read_text())
        assert value["queue_depth"] == 2 and value["unadmitted_packets"] == 1
        assert value["delivered_packets"] == 0
    finally:
        capture.close()
        sender.close()
    assert not capture.reader_thread.is_alive()
    assert (
        json.loads((capture.directory / "transport-unprocessed.json").read_text())["queued_packets"]
        == 2
    )


def test_disconnect_does_not_turn_pending_data_into_success(tmp_path):
    capture, sender, _ = fixture_channel(tmp_path / "session", separated=True)
    sender.close()
    try:
        wait_for(lambda: capture.reader_error is not None)
        with pytest.raises(CaptureUnavailable, match="DISCONNECTED"):
            capture.receive()
        with pytest.raises(CaptureUnavailable):
            capture.statistics()
        assert not capture.is_live()
    finally:
        capture.close()


def test_receiver_stop_unblocks_sender_and_joins_reader(tmp_path):
    capture, sender, s = fixture_channel(tmp_path / "session", separated=True)
    _, records = messages(s, fixture_packets(1, s.interface_id, datetime.now(UTC)))
    for record in list(records)[:2]:
        send(sender, record)
    wait_for(lambda: capture.packets.qsize() == 1)
    capture.close()
    capture.close()
    try:
        assert not capture.reader_thread.is_alive()
        assert capture.delivered == 0
        assert capture.receive() is None
        with pytest.raises(CaptureUnavailable, match="FINAL_COUNTERS_MISSING"):
            capture.statistics()
        assert (capture.directory / "transport-unprocessed.json").exists()
        with pytest.raises(OSError):
            send(sender, list(records)[0])
    finally:
        sender.close()


@pytest.mark.parametrize("fault", ["duplicate_packet", "counter_gap", "drop"])
def test_reader_does_not_deliver_after_integrity_failure(tmp_path, fault):
    capture, sender, s = fixture_channel(tmp_path / "session", separated=True)
    try:
        _, records = messages(s, fixture_packets(2, s.interface_id, datetime.now(UTC)))
        send(sender, records[0])
        send(sender, records[1])
        if fault == "duplicate_packet":
            bad = records[1]
        elif fault == "counter_gap":
            bad = records[2].model_copy(update={"counter_sequence": 99})
        else:
            bad = records[2].model_copy(
                update={
                    "capture_drops": 1,
                    "capture_drops_total": 1,
                    "counter_status": "CAPTURE_DROPS_DETECTED",
                }
            )
        send(sender, bad)
        wait_for(lambda: capture.reader_error is not None)
        with pytest.raises(CaptureUnavailable):
            capture.receive()
        assert capture.delivered == 0 and not capture.is_live()
        assert not (capture.directory / "verified-closed.json").exists()
    finally:
        capture.close()
        sender.close()


def test_actual_missing_counter_55_and_timeout_diagnostic_is_preserved(tmp_path):
    capture, sender, s = fixture_channel(tmp_path / "session")
    capture.counter_sequence = 54
    capture.counter_totals = [50, 0]
    capture.start_reader()
    try:
        send(
            sender,
            Message(
                kind="CLOSED",
                session_id=s.session_id,
                counter_sequence=56,
                kernel_packets=170,
                capture_drops=0,
                kernel_packets_total=258,
                capture_drops_total=0,
                counter_status="COUNTER_VERIFIED",
                error="HELPER_TRANSPORT_TIMEOUT",
            ),
        )
        wait_for(lambda: capture.reader_error is not None)
        assert capture.counter_issue["helper_error"] == "HELPER_TRANSPORT_TIMEOUT"
        assert capture.counter_issue["error"] == "HELPER_CAPTURE_COUNTER_INTEGRITY_FAILED"
        with pytest.raises(CaptureUnavailable):
            capture.statistics()
    finally:
        capture.close()
        sender.close()


def test_clean_closed_waits_for_processor_drain(tmp_path):
    capture, sender, s = fixture_channel(tmp_path / "session", separated=True)
    try:
        packets = fixture_packets(3, s.interface_id, datetime.now(UTC))
        _, records = messages(s, packets)
        for record in records:
            send(sender, record)
        wait_for(lambda: capture.terminal is not None)
        assert not capture.stop.is_set() and not capture.is_live()
        assert [capture.receive() for _ in packets] == packets
        assert capture.receive() is None and capture.stop.is_set()
        assert capture.statistics() == (3, 0) and capture.statistics() == (0, 0)
    finally:
        capture.close()
        sender.close()


def test_unexpected_reader_exit_is_not_live_or_ready(tmp_path, monkeypatch):
    capture, sender, _ = fixture_channel(tmp_path / "session")
    monkeypatch.setattr(capture, "_read_loop", lambda: None)
    capture.start_reader()
    capture.reader_thread.join(1)
    try:
        service = LiveMonitoring(tmp_path)
        service.capture, service.session = capture, capture.session
        service.state = "LIVE_COLLECTION"
        snapshot = service.snapshot()
        assert snapshot["state"] == "ERROR" and not snapshot["collection_live"]
        assert snapshot["last_error"] == "HELPER_READER_EXITED_UNEXPECTEDLY"
        with pytest.raises(CaptureUnavailable, match="EXITED_UNEXPECTEDLY"):
            capture.open()
        assert not capture.is_live()
    finally:
        capture.close()
        sender.close()


def test_reader_start_failure_has_safe_cleanup(tmp_path, monkeypatch):
    capture, sender, _ = fixture_channel(tmp_path / "session")

    def fail(self):
        raise RuntimeError("simulated thread startup failure")

    monkeypatch.setattr(threading.Thread, "start", fail)
    try:
        with pytest.raises(CaptureUnavailable, match="START_FAILED"):
            capture.start_reader()
        assert capture.reader_thread is None
    finally:
        capture.close()
        sender.close()


def test_stalled_helper_heartbeat_deadline_stops_reader(tmp_path):
    capture, sender, _ = fixture_channel(tmp_path / "session", separated=True)
    capture.last_heartbeat = time.monotonic() - 3
    try:
        wait_for(lambda: capture.reader_error is not None)
        assert "HEARTBEAT_OR_PROCESS_STALE" in capture.reader_error
        with pytest.raises(CaptureUnavailable):
            capture.statistics()
    finally:
        capture.close()
        sender.close()


@pytest.mark.parametrize("error", ["HELPER_TRANSPORT_TIMEOUT", "HELPER_WATCHDOG_EXPIRED"])
def test_terminal_error_is_classified_without_success_receipt(tmp_path, error):
    capture, sender, s = fixture_channel(tmp_path / "session", separated=True)
    try:
        send(
            sender,
            Message(
                kind="CLOSED",
                session_id=s.session_id,
                counter_sequence=2,
                kernel_packets=0,
                capture_drops=0,
                kernel_packets_total=0,
                capture_drops_total=0,
                counter_status="COUNTER_VERIFIED",
                error=error,
            ),
        )
        wait_for(lambda: capture.reader_error is not None)
        assert capture.reader_error == error
        assert not (capture.directory / "verified-closed.json").exists()
    finally:
        capture.close()
        sender.close()


def test_queued_authenticated_heartbeat_is_read_before_silence_judgment(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "session")
    capture.last_heartbeat = time.monotonic() - 3  # Descheduled reader, buffered message.
    try:
        send(
            sender,
            Message(
                kind="HEARTBEAT",
                session_id=session.session_id,
                kernel_packets=0,
                capture_drops=0,
                counter_sequence=2,
                counter_status="COUNTER_VERIFIED",
                kernel_packets_total=0,
                capture_drops_total=0,
            ),
        )
        capture.start_reader()
        wait_for(lambda: capture.counter_sequence == 2 or capture.reader_error is not None)
        assert capture.reader_error is None and capture.counter_sequence == 2
        assert time.monotonic() - capture.last_heartbeat < 1
        assert not (capture.directory / "transport-failure.json").exists()
    finally:
        capture.close()
        sender.close()


def test_queued_replayed_heartbeat_cannot_revive_stale_reader(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "session")
    capture.last_heartbeat = time.monotonic() - 3
    try:
        send(
            sender,
            Message(
                kind="HEARTBEAT",
                session_id=session.session_id,
                kernel_packets=0,
                capture_drops=0,
                counter_sequence=1,  # READY already used one.
                counter_status="COUNTER_VERIFIED",
                kernel_packets_total=0,
                capture_drops_total=0,
            ),
        )
        capture.start_reader()
        wait_for(lambda: capture.reader_error is not None)
        assert capture.reader_error == "HELPER_CAPTURE_COUNTER_INTEGRITY_FAILED"
        assert not capture.alive
        value = json.loads((capture.directory / "transport-failure.json").read_text())
        assert value["stage"] == "AUTHENTICATED_HELPER_READER"
        assert value["heartbeat_deadline_seconds"] == 2
        assert value["session"] == str(session.session_id)
    finally:
        capture.close()
        sender.close()
