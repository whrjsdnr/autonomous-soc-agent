"""Completion/count/window guards on ordinary Unix IPC fixtures only."""

import time
from collections import deque
from datetime import timedelta

import pytest
from tests.live_network_performance import fixture_packets, messages
from tests.live_transport_diagnostics import fixture_channel

from soc_agent.security_ai.research.live_service import LiveMonitoring
from soc_agent.state.evidence import utc_now


def wait_for(predicate):
    deadline = time.monotonic() + 2
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("FIXTURE_COMPLETION_NOT_REACHED")
        time.sleep(0.002)


@pytest.mark.parametrize(
    "fields,approved",
    [
        ({}, True),
        ({"sent_packets": None}, False),
        ({"sent_packets": 9}, False),
        ({"received_frames": 7}, False),
        ({"elapsed_seconds": 61.0}, False),
    ],
)
def test_clean_counter_alone_never_authorizes_missing_or_undrained_metadata(
    tmp_path, fields, approved
):
    capture, sender, session = fixture_channel(tmp_path / "session", separated=True)
    packets = fixture_packets(8, session.interface_id, utc_now() - timedelta(seconds=45))
    _, records = messages(session, packets)
    records[-1] = records[-1].model_copy(
        update={"sent_packets": 8, "received_frames": 16, "elapsed_seconds": 1.0, **fields}
    )
    try:
        for record in records:
            sender.sendall(record.model_dump_json(exclude_none=True).encode())
        wait_for(lambda: capture.terminal is not None)
        assert not capture.completion_verified()
        assert [capture.receive() for _ in packets] == packets
        assert capture.completion_verified() is approved
        assert capture.flow_watermark(utc_now()) == packets[-1].timestamp
    finally:
        capture.close()
        sender.close()


def test_empty_staging_during_capture_does_not_advance_flow_clock_to_processing_time(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "session", separated=True)
    packets = fixture_packets(1, session.interface_id, utc_now() - timedelta(seconds=45))
    _, records = messages(session, packets)
    records = deque(list(records)[:-1])  # Helper has not ended; no final counter proof.
    try:
        for record in records:
            sender.sendall(record.model_dump_json(exclude_none=True).encode())
        wait_for(lambda: capture.packets.qsize() == 1)
        packet = capture.receive()
        assert capture.packets.empty() and capture.terminal is None
        assert capture.flow_watermark(utc_now()) == packet.timestamp
        assert not capture.completion_verified()
    finally:
        capture.close()
        sender.close()


def test_no_pending_model_consumer_before_successful_monitor_finalization(tmp_path):
    from types import SimpleNamespace

    from tests.unit.live_network.test_parity import request

    service = LiveMonitoring(tmp_path)
    service.capture = SimpleNamespace(
        ready=True,
        counter_issue=None,
        reader_failed=lambda: False,
        closed=SimpleNamespace(is_set=lambda: False),
        completion_verified=lambda: True,
    )
    service.monitor = SimpleNamespace(metrics={"finalization": "BLOCKED", "last_error": None})
    with pytest.raises(ValueError, match="AUTHENTICATED_SOURCE"):
        service.validate_native_source(request())
    assert service.task is None and service.demo is None
