"""Synthetic wire/clock inputs: independent PCAP parser + hand calculation, NOT native capture."""

import socket
import struct
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from soc_agent.security_ai.operational.network_capture.flows import FlowTable
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from soc_agent.security_ai.research.live_input import (
    LiveRequest,
    parity_check,
    produce,
    producer_packets,
)


def wire(*, reverse=False, length=40, flags=2, ipv6=False, tcp=True):
    addresses = ("2001:db8::1", "2001:db8::2") if ipv6 else ("192.0.2.1", "192.0.2.2")
    ports = (1000, 2000)
    if reverse:
        addresses, ports = addresses[::-1], ports[::-1]
    size = 40 if ipv6 else 20
    segment = (
        struct.pack("!HHIIBBHHH", *ports, 1, 0, 0x50, flags, 4096, 0, 0)
        if tcp
        else struct.pack("!HHHH", *ports, length - size, 0)
    )
    payload = b"x" * (length - size - len(segment))
    segment += payload
    if ipv6:
        header = struct.pack("!IHBB", 6 << 28, len(segment), 6 if tcp else 17, 64)
        header += b"".join(socket.inet_pton(socket.AF_INET6, a) for a in addresses)
    else:
        header = struct.pack("!BBHHHBBH", 0x45, 0, length, 1, 0, 64, 6 if tcp else 17, 0)
        header += b"".join(socket.inet_aton(a) for a in addresses)
    return b"\0" * 12 + struct.pack("!H", 0x86DD if ipv6 else 0x0800) + header + segment


def observation(body, ns, native=True):
    seconds, nanos = divmod(ns, 10**9)
    return parse_packet(
        body,
        interface_id="a" * 64,
        timestamp=datetime.fromtimestamp(seconds, UTC).replace(microsecond=nanos // 1000),
        capture_timestamp_ns=ns if native else None,
        direction="OUTBOUND",
        native=native,
    )


def request(*, native=True, ipv6=False, tcp=True):
    base = 60 if ipv6 else 40
    packets = tuple(
        observation(
            wire(reverse=i == 1, length=base + 20 * i, flags=[2, 16, 1][i], ipv6=ipv6, tcp=tcp),
            1_000_000_000 + i * 500_000_000,
            native,
        )
        for i in range(3)
    )
    return LiveRequest(
        research_mode=True,
        origin="NATIVE_AF_PACKET" if native else "FIXTURE",
        profile="quality",
        invocation_id=uuid4(),
        capture_session=uuid4(),
        flow_id="b" * 64,
        provenance_digest="c" * 64,
        packet_event_ids=tuple(uuid4() for _ in packets),
        packets=packets,
    )


@pytest.mark.parametrize("ipv6,tcp", [(False, False), (False, True), (True, False), (True, True)])
def test_wire_parsers_origins_and_independent_hand_reference(ipv6, tcp):
    from ml.ctu13.pcap import Record
    from ml.ctu13.pcap import parse_packet as offline
    from ml.verified_producers.network_v1_1 import network_features

    value = request(ipv6=ipv6, tcp=tcp)
    base = 60 if ipv6 else 40
    other = tuple(
        offline(
            Record(
                i,
                1_000_000_000 + i * 500_000_000,
                base + 20 * i + 14,
                base + 20 * i + 14,
                wire(reverse=i == 1, length=base + 20 * i, flags=[2, 16, 1][i], ipv6=ipv6, tcp=tcp),
            ),
            "d" * 64,
        )
        for i in range(3)
    )
    for p, q in zip(producer_packets(value), other, strict=True):
        assert (p.timestamp_ns, p.endpoints, p.ip_length, p.tcp_flags) == (
            q.timestamp_ns,
            q.endpoints,
            q.ip_length,
            q.tcp_flags,
        )
    expected = [
        1,
        2,
        1,
        base * 2 + 40,
        base + 20,
        base,
        base + 40,
        base + 20,
        (800 / 3) ** 0.5,
        int(tcp),
        int(tcp),
        0,
        0.5,
        0.5,
    ]
    expected = tuple(struct.unpack("!f", struct.pack("!f", n))[0] for n in expected)
    actual = produce(value)
    assert actual.values == expected
    assert (
        network_features(other, source_origin="OFFLINE_PCAP", source_identity="d" * 64).values
        == expected
    )
    assert actual.source_origin == "NATIVE_AF_PACKET"
    parity_check()


@pytest.mark.parametrize("gap", [29_999_999_999, 30_000_000_000, 30_000_000_001])
def test_native_nanosecond_idle_boundary(gap):
    table = FlowTable(CaptureConfig(interface="lo"))
    first = observation(wire(), 1_000_000_999)
    second = observation(wire(reverse=True), 1_000_000_999 + gap)
    table.add(first, "first")
    expired = table.add(second, "second")
    assert bool(expired) == (gap >= 30_000_000_000)


def test_periodic_expiry_does_not_round_native_time_early():
    table = FlowTable(CaptureConfig(interface="lo"))
    table.add(observation(wire(), 1_000_000_999), "first")
    assert not table.expire(datetime.fromtimestamp(31, UTC))
    assert (
        table.expire(datetime.fromtimestamp(31, UTC).replace(microsecond=1))[0].close_reason
        == "IDLE_TIMEOUT"
    )


def test_training_and_native_flow_segmentation_share_timeout_windows():
    from ml.ctu13.flows import Flows

    value = request()
    native = FlowTable(CaptureConfig(interface="lo"))
    offline = Flows()
    observed = []
    for i, p in enumerate(value.packets):
        assert not native.add(p, str(value.packet_event_ids[i]))
    for p in producer_packets(value):
        assert not offline.add(p)
    last = observation(wire(), 32_000_000_000)
    observed.extend(native.add(last, "next"))
    from dataclasses import replace

    done = offline.add(
        replace(producer_packets(value)[0], event_id="next", timestamp_ns=32_000_000_000)
    )
    assert len(observed) == len(done) == 1
    assert observed[0].close_reason == done[0].closure == "IDLE_TIMEOUT"
    assert observed[0].source_event_ids == tuple(p.event_id for p in done[0].packets)


@pytest.mark.parametrize("change", ["origin", "order", "duplicate", "config", "nan", "dns"])
def test_bad_packet_contract_rejected(change):
    value = request().model_dump(mode="json")
    if change == "origin":
        value["origin"] = "OFFLINE_PCAP"
    if change == "order":
        value["packets"] = value["packets"][::-1]
    if change == "duplicate":
        value["packet_event_ids"][1] = value["packet_event_ids"][0]
    if change == "config":
        value["producer_configuration_digest"] = "0" * 64
    if change == "nan":
        value["packets"][0]["ip_length"] = float("nan")
    if change == "dns":
        value["packets"][0]["raw_payload"] = "forbidden"
    with pytest.raises(ValueError):
        LiveRequest.model_validate(value)
