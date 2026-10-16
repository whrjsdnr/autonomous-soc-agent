"""Arithmetic reference, event-time expiry and explicit bounded-state failures."""

import math
import random
import struct
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.streaming_network_support import packet

from soc_agent.security_ai.operational.network_capture.streaming_flow import StreamingFlows
from soc_agent.security_ai.research.live_input import LiveRequest, produce


def owner():
    return SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))


def add(table, t, **kwargs):
    return table.add(packet(owner(), t, **kwargs), uuid4())


def f32(x):
    return struct.unpack("!f", struct.pack("!f", x))[0]


def test_manual_reference_and_unchanged_producer_across_origins():
    table = StreamingFlows()
    add(table, 0, length=40, flags=2)
    add(table, 0.5, length=60, flags=16, reverse=True)
    add(table, 1, length=80, flags=1)
    result = add(table, 31)[0]
    expected = tuple(
        map(f32, (1, 2, 1, 120, 60, 40, 80, 60, math.sqrt(800 / 3), 1, 1, 0, 0.5, 0.5))
    )
    assert result.values == expected
    request = LiveRequest(
        research_mode=True,
        origin="FIXTURE",
        profile="quality",
        invocation_id=uuid4(),
        capture_session=uuid4(),
        flow_id=result.flow.flow_id,
        provenance_digest="b" * 64,
        packets=result.packets,
        packet_event_ids=result.identities,
    )
    assert produce(request).values == expected
    assert result.flow.close_reason == "IDLE_TIMEOUT"
    assert result.flow.forward_bytes == 148  # Ethernet bytes; feature uses IP bytes120.
    assert table.bytes > 0
    table.close()
    assert table.bytes == 0 and not table.stats


@pytest.mark.parametrize("seed", range(12))
def test_incremental_against_batch_producer(seed):
    rng = random.Random(seed)
    table = StreamingFlows()
    t = 0
    for _ in range(30):
        t += rng.random() / 10
        add(
            table,
            t,
            reverse=bool(rng.getrandbits(1)),
            length=rng.randrange(40, 1500),
            flags=rng.randrange(32),
        )
    result = add(table, t + 30)[0]
    request = LiveRequest(
        research_mode=True,
        origin="FIXTURE",
        profile="edge",
        invocation_id=uuid4(),
        capture_session=uuid4(),
        flow_id=result.flow.flow_id,
        provenance_digest="c" * 64,
        packets=result.packets,
        packet_event_ids=result.identities,
    )
    assert result.values == produce(request).values


@pytest.mark.parametrize(("time", "expected"), [(29.999999999, False), (30, True)])
def test_idle_event_time_boundary(time, expected):
    table = StreamingFlows()
    add(table, 0)
    assert bool(add(table, time)) is expected


def test_active_timeout_and_packet_limit_are_distinct():
    table = StreamingFlows()
    for t in range(0, 120, 10):
        assert not add(table, t)
    assert add(table, 120)[0].flow.close_reason == "ACTIVE_TIMEOUT"
    table = StreamingFlows()
    for i in range(127):
        assert not add(table, i / 100)
    assert add(table, 1.27)[0].flow.close_reason == "PACKET_LIMIT"
    assert table.bytes == 0


@pytest.mark.parametrize("reason", ["SHUTDOWN", "RESTART_GAP"])
def test_no_wall_clock_expiry_and_incomplete_cleanup(reason):
    table = StreamingFlows()
    add(table, 0)
    result = table.close(reason)
    assert result[0].flow.close_reason == reason
    assert table.bytes == 0
    assert not table.close(reason)


def test_capacity_rejects_without_losing_existing_state():
    table = StreamingFlows(max_flows=1)
    add(table, 0)
    with pytest.raises(ValueError, match="ACTIVE_FLOW_BACKPRESSURE"):
        add(table, 1, port=3000)
    assert len(table.packets) == 1 and table.observed == 1
    assert add(table, 30, port=3000)[0].flow.close_reason == "IDLE_TIMEOUT"


def test_metadata_limit_duplicate_and_timestamp_fail_closed():
    table = StreamingFlows(metadata_bytes=8192)
    p = packet(owner(), 1)
    identity = uuid4()
    table.add(p, identity)
    with pytest.raises(ValueError, match="DUPLICATE"):
        table.add(p, identity)
    with pytest.raises(ValueError, match="TIME_REVERSED"):
        add(table, 0)
    with pytest.raises(ValueError, match="MEMORY_BACKPRESSURE"):
        for i in range(100):
            add(table, 2 + i / 100)
    assert table.bytes <= 8192
    table.close("RESTART_GAP")
    assert table.bytes == 0
