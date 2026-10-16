"""Mock kernel timespec and immutable synthetic metadata; never opens AF_PACKET."""

import json
import math
import socket
import struct
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.unit.network_capture.test_capture import SocketFixture
from tests.unit.network_capture.test_packets import IDENTITY

from soc_agent.security_ai.operational.network_capture.capture import PacketCapture
from soc_agent.security_ai.operational.network_capture.models import (
    CaptureConfig,
    PacketObservation,
)
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
from soc_agent.security_ai.operational.network_capture.streaming_flow import (
    PacketTimeReversed,
    Statistics,
    StreamingFlows,
)
from soc_agent.security_ai.research.live_input import LiveRequest, produce, timestamp_ns

BASE = 1_800_000_000 * 10**9


def observed(ns, *, kind=4):
    raw = SocketFixture()
    raw.control = [(socket.SOL_SOCKET, 35, struct.pack("@ll", *divmod(ns, 10**9)))]
    raw.address = ("lo", 0x800, kind, 1, b"")
    capture = PacketCapture(CaptureConfig(interface="lo"))
    capture.socket = raw  # Mock recvmsg only, no socket constructor/open.
    body, stamp, direction, actual = capture.receive()
    capture.close()
    value = parse_packet(
        body,
        interface_id=IDENTITY,
        timestamp=stamp,
        direction=direction,
        native=True,
        capture_timestamp_ns=actual,
    )
    return value.model_copy(update={"dns": None, "dns_status": "DNS_HEADERS_ONLY"})


def request(packets):
    return LiveRequest(
        research_mode=True,
        origin="NATIVE_AF_PACKET",
        profile="quality",
        invocation_id=uuid4(),
        capture_session=uuid4(),
        flow_id="a" * 64,
        provenance_digest="b" * 64,
        packets=packets,
        packet_event_ids=tuple(uuid4() for _ in packets),
    )


@pytest.mark.parametrize(
    "ns", [BASE, BASE + 1, BASE + 999, BASE + 1000, BASE + 999_999_999, BASE + 10**9]
)
def test_timespec_json_roundtrip_preserves_exact_integer_ns(ns):
    packet = observed(ns)
    message = StreamMessage(kind="PACKET", session_id=uuid4(), sequence=1, packet=packet)
    restored = StreamMessage.model_validate_json(message.model_dump_json()).packet
    assert restored == packet
    assert timestamp_ns(restored) == ns
    assert restored.timestamp.microsecond == ns % 10**9 // 1000
    assert PacketObservation.model_validate_json(packet.model_dump_json()) == packet


@pytest.mark.parametrize("regression", [1, 1_000_000, 500_000_000, 1_500_000_000])
def test_regression_rejected_before_mutation_even_below_datetime_precision(regression):
    table = StreamingFlows()
    first, rejected = observed(BASE + 2 * 10**9), observed(BASE + 2 * 10**9 - regression)
    table.add(first, uuid4())
    retained = (table.bytes, table.observed, table.last_ns)
    with pytest.raises(PacketTimeReversed) as caught:
        table.add(rejected, uuid4())
    assert caught.value.scope == "GLOBAL"
    assert caught.value.previous_ns - caught.value.rejected_ns == regression
    assert str(caught.value) == "STREAM_TIME_REVERSED"
    assert (table.bytes, table.observed, table.last_ns) == retained
    table.close("RESTART_GAP")
    assert table.bytes == 0


def test_same_datetime_does_not_hide_one_ns_regression():
    first, second = observed(BASE + 999), observed(BASE + 998)
    assert first.timestamp == second.timestamp
    table = StreamingFlows()
    table.add(first, uuid4())
    with pytest.raises(PacketTimeReversed):
        table.add(second, uuid4())


@pytest.mark.parametrize("mutation", ["float_ns", "missing_ns", "datetime_shift"])
def test_lossy_or_inconsistent_native_serialization_is_rejected(mutation):
    value = observed(BASE + 999).model_dump(mode="json")
    if mutation == "float_ns":
        value["capture_timestamp_ns"] = float(value["capture_timestamp_ns"])
    elif mutation == "missing_ns":
        value["capture_timestamp_ns"] = None
    else:
        value["timestamp"] = observed(BASE + 1000).timestamp.isoformat()
    with pytest.raises(ValidationError):
        PacketObservation.model_validate_json(json.dumps(value))


def test_equal_timestamps_are_distinct_packets_and_first_seen_direction_matters():
    from tests.streaming_network_support import packet

    owner = SimpleNamespace(session=SimpleNamespace(interface_id=IDENTITY))
    original = tuple(
        packet(owner, 0, reverse=r, length=n) for r, n in [(False, 40), (True, 60), (False, 80)]
    )
    # Explicit fixture, no native origin claim. Independent arithmetic below.
    from ml.verified_producers.network import Packet
    from ml.verified_producers.network_v1_1 import network_features

    def features(values):
        raw = tuple(
            Packet(
                event_id=p.raw_frame_digest,
                capture_session_id="explicit-equal-time-fixture",
                interface_id=IDENTITY,
                timestamp_ns=BASE,
                transport=p.transport,
                source_address=str(p.source_address),
                destination_address=str(p.destination_address),
                source_port=p.source_port,
                destination_port=p.destination_port,
                ip_length=p.ip_length,
                tcp_flags=p.tcp_flags,
            )
            for p in values
        )
        return network_features(raw, source_origin="FIXTURE", source_identity="c" * 64)

    left, right = features(original), features((original[1], original[0], original[2]))
    assert left.values[:5] == (0, 2, 1, 120, 60)
    assert right.values[:5] == (0, 1, 2, 60, 120)
    assert left.values[-2:] == (0, 0)
    assert left.source_digest != right.source_digest


def test_independent_one_ns_reference_matches_unchanged_producer():
    packets = (observed(BASE + 100), observed(BASE + 101), observed(BASE + 102))
    table = StreamingFlows()
    for value, identity in zip(packets, request(packets).packet_event_ids, strict=True):
        table.add(value, identity)
    completed = table.add(observed(BASE + 30 * 10**9 + 102), uuid4())[0]
    actual = produce(request(packets))

    def f32(n):
        return struct.unpack("!f", struct.pack("!f", n))[0]

    assert completed.values == actual.values
    assert actual.values[0] == f32(2e-9)
    assert actual.values[-2:] == (f32(1e-9), f32(1e-9))
    assert math.isfinite(actual.values[0])


def test_raw_regression_is_rejected_not_repaired_by_sorting():
    from ml.verified_producers.network_v1_1 import network_features

    from soc_agent.security_ai.research.live_input import producer_packets

    sorted_packets = (observed(BASE), observed(BASE + 100), observed(BASE + 200))
    valid = request(sorted_packets)
    raw = producer_packets(valid)
    with pytest.raises(ValueError, match="ORDER_OR_TIMEOUT"):
        network_features(
            (raw[1], raw[0], raw[2]), source_origin="FIXTURE", source_identity="c" * 64
        )
    assert (
        network_features(raw, source_origin="FIXTURE", source_identity="c" * 64).values
        == produce(valid).values
    )
    # Sorted computation is a hypothetical arithmetic reference, not a promoted native flow.


def test_flow_statistics_rejects_its_own_event_time_mismatch():
    stats = Statistics(observed(BASE + 1))
    stats.add(observed(BASE + 1))
    with pytest.raises(PacketTimeReversed) as caught:
        stats.add(observed(BASE))
    assert caught.value.scope == "FLOW"
    assert stats.count == 1
