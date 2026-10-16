"""Control-message drain regression; all packet metadata is synthetic, never captured."""

from datetime import UTC, datetime

import pytest
from tests.live_network_performance import (
    SingleRecordReceiver,
    fixture_packets,
    messages,
    runtime_trial,
)

from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    interface_identity,
)
from soc_agent.security_ai.operational.network_capture.helper_transport import (
    HelperCapture,
    Message,
)
from soc_agent.security_ai.operational.network_capture.live_session import prepare
from soc_agent.security_ai.research.models import digest


@pytest.fixture
def receiver(tmp_path):
    session = prepare(tmp_path / "observer")
    capture = HelperCapture(tmp_path / "observer", session)
    packets = fixture_packets(2, session.interface_id, datetime.now(UTC))
    ready, records = messages(session, packets)
    capture.accept_counters(ready)
    capture.ready = ready
    capture.alive = True

    def pop():
        if not records:
            raise BlockingIOError
        return records.popleft()

    capture.message = pop
    try:
        yield capture, session, packets, records
    finally:
        capture.close()


def test_heartbeat_does_not_hide_already_buffered_packet(receiver):
    capture, _, packets, _ = receiver
    assert capture.receive() == packets[0]
    assert capture.counter_sequence == 2 and capture.statistics() == (1, 0)
    assert capture.receive() == packets[1]
    assert capture.receive() is None and not capture.alive
    assert capture.terminal.kind == "CLOSED"


def test_baseline_reference_reproduces_false_empty_on_control(receiver):
    capture, _, packets, _ = receiver
    assert SingleRecordReceiver.receive(capture) is None
    assert SingleRecordReceiver.receive(capture) == packets[0]


def test_control_batch_is_bounded_and_does_not_skip_queued_data(receiver):
    capture, s, packets, records = receiver
    records.clear()
    for i in range(65):
        records.append(
            Message(
                kind="HEARTBEAT",
                session_id=s.session_id,
                counter_sequence=i + 2,
                kernel_packets=0,
                capture_drops=0,
                kernel_packets_total=0,
                capture_drops_total=0,
                counter_status="COUNTER_VERIFIED",
            )
        )
    records.append(Message(kind="PACKET", session_id=s.session_id, sequence=1, packet=packets[0]))
    assert capture.receive() is None
    assert capture.counter_sequence == 65 and len(records) == 2
    assert capture.control_batch == 64
    assert capture.receive() == packets[0]
    assert not records


def test_empty_socket_returns_without_spinning(receiver):
    capture, _, _, records = receiver
    records.clear()
    calls = []

    def empty():
        calls.append(1)
        raise BlockingIOError

    capture.message = empty
    assert capture.receive() is None and calls == [1]


def test_observed_drop_96_packets_87_lost_stops_before_next_packet(receiver):
    capture, s, packets, records = receiver
    records.clear()
    capture.counter_sequence = 30
    capture.counter_totals = [272, 0]
    records.append(
        Message(
            kind="HEARTBEAT",
            session_id=s.session_id,
            counter_sequence=31,
            kernel_packets=96,
            capture_drops=87,
            kernel_packets_total=368,
            capture_drops_total=87,
            counter_status="CAPTURE_DROPS_DETECTED",
        )
    )
    records.append(Message(kind="PACKET", session_id=s.session_id, sequence=1, packet=packets[0]))
    with pytest.raises(CaptureUnavailable, match="DROPS_DETECTED"):
        capture.receive()
    assert len(records) == 1 and capture.sequence == 0 and not capture.alive
    assert capture.counter_issue["capture_drops"] == 87
    with pytest.raises(CaptureUnavailable, match="DROPS_DETECTED"):
        capture.statistics()


def test_bad_interval_inside_batch_stops_without_forwarding_packet(receiver):
    capture, s, _, records = receiver
    records.appendleft(
        Message(
            kind="HEARTBEAT",
            session_id=s.session_id,
            counter_sequence=99,
            kernel_packets=0,
            capture_drops=0,
            kernel_packets_total=0,
            capture_drops_total=0,
            counter_status="COUNTER_VERIFIED",
        )
    )
    with pytest.raises(CaptureUnavailable, match="COUNTER_INTEGRITY_FAILED"):
        capture.receive()
    assert capture.sequence == 0


def test_duplicate_packet_inside_control_stream_is_rejected(receiver):
    capture, s, packets, records = receiver
    assert capture.receive() == packets[0]
    records.appendleft(
        Message(kind="PACKET", session_id=s.session_id, sequence=1, packet=packets[0])
    )
    with pytest.raises(CaptureUnavailable, match="BINDING_MISMATCH"):
        capture.receive()


@pytest.mark.asyncio
async def test_actual_runtime_fixture_batch_preserves_queue_audit_and_no_inference(tmp_path):
    packets = fixture_packets(4, interface_identity("lo"), datetime.now(UTC))
    before = digest([p.model_dump(mode="json") for p in packets])
    result = await runtime_trial(tmp_path, HelperCapture, packets)
    assert result["packets"] == result["kernel_packets"] == 4
    assert result["capture_drops"] == 0 and result["audit_verified"]
    assert not result["queue"].get("PENDING", 0) and not result["queue"].get("POISON", 0)
    assert before == digest([p.model_dump(mode="json") for p in packets])
