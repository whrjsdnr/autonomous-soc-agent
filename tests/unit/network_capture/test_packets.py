"""Explicit binary Fixtures, never described as live packet capture or Golden Pair."""

import hashlib
import socket
import struct
from datetime import timedelta

import pytest
from pydantic import ValidationError

from soc_agent.security_ai.operational.network_capture.flows import FlowTable
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig, model_gates
from soc_agent.security_ai.operational.network_capture.parsing import (
    PacketRejected,
    dns_message,
    parse_packet,
)
from soc_agent.state.evidence import utc_now

IDENTITY = "a" * 64


def dns(name=b"Private123"):
    return (
        struct.pack("!6H", 7, 0x100, 1, 0, 0, 0)
        + bytes([len(name)])
        + name
        + b"\x07example\0"
        + struct.pack("!HH", 1, 1)
    )


def frame(*, ipv6=False, tcp=False, reverse=False, payload=None, port=53):
    body = dns() if payload is None else payload
    sport, dport = (port, 45678) if reverse else (45678, port)
    if tcp:
        body = struct.pack("!H", len(body)) + body
        segment = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x12, 4096, 0, 0) + body
    else:
        segment = struct.pack("!HHHH", sport, dport, 8 + len(body), 0) + body
    addresses = ("2001:db8::1", "2001:db8::2") if ipv6 else ("192.0.2.1", "192.0.2.2")
    if reverse:
        addresses = addresses[::-1]
    if ipv6:
        data = (
            struct.pack("!IHBB", 6 << 28, len(segment), 6 if tcp else 17, 64)
            + b"".join(socket.inet_pton(socket.AF_INET6, a) for a in addresses)
            + segment
        )
    else:
        data = (
            struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, 6 if tcp else 17, 0)
            + b"".join(socket.inet_aton(a) for a in addresses)
            + segment
        )
    return b"\0" * 12 + struct.pack("!H", 0x86DD if ipv6 else 0x0800) + data


def packet(data=None, **kwargs):
    return parse_packet(
        frame() if data is None else data,
        interface_id=IDENTITY,
        timestamp=kwargs.pop("timestamp", utc_now()),
        direction="OUTBOUND",
        native=False,
        **kwargs,
    )


@pytest.mark.parametrize("ipv6,tcp", [(False, False), (False, True), (True, False), (True, True)])
def test_real_parser_binary_fixture_and_privacy(ipv6, tcp):
    value = packet(frame(ipv6=ipv6, tcp=tcp))
    assert value.ip_version == (6 if ipv6 else 4)
    assert value.transport == ("tcp" if tcp else "udp")
    assert value.dns and value.dns.query_name is None and value.dns.query_type == 1
    assert "Private123" not in value.model_dump_json()
    assert value.frame_length == len(frame(ipv6=ipv6, tcp=tcp))
    assert value.timestamp_origin == "FIXTURE"


def test_dns_case_preserved_only_with_explicit_retention():
    value = packet(retain_name=True)
    assert value.dns.query_name == "Private123.example"
    assert (
        value.dns.query_name_digest
        != packet(frame(payload=dns(b"private123"))).dns.query_name_digest
    )
    assert packet(frame(tcp=True)).tcp_flags == 0x12
    assert packet(frame(tcp=True)).tcp_window == 4096


@pytest.mark.parametrize("length", [0, 1, 13, 20, 33, 40, 45])
def test_truncated_packet_is_not_valid_input(length):
    with pytest.raises(PacketRejected):
        packet(frame()[:length])


def test_fragment_esp_and_overlong_extension_are_rejected():
    ipv4 = bytearray(frame())
    ipv4[20:22] = struct.pack("!H", 0x2000)
    with pytest.raises(PacketRejected, match="FRAGMENT"):
        packet(bytes(ipv4))
    ipv6 = bytearray(frame(ipv6=True))
    ipv6[20] = 44
    with pytest.raises(PacketRejected, match="FRAGMENT"):
        packet(bytes(ipv6))
    ipv6[20] = 0
    ipv6[54:56] = bytes([17, 255])
    with pytest.raises(PacketRejected, match="EXTENSION"):
        packet(bytes(ipv6))


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\0" * 11,
        struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c",
        struct.pack("!6H", 1, 0, 2, 0, 0, 0) + b"\0" * 12,
    ],
)
def test_malformed_dns_rejected_without_raw_error(data):
    with pytest.raises(PacketRejected) as error:
        dns_message(data, retain_name=False)
    assert len(str(error.value)) < 64


def test_dns_response_and_encrypted_visibility_not_guessed():
    raw = bytearray(dns())
    raw[2:4] = struct.pack("!H", 0x8183)
    assert packet(frame(payload=bytes(raw), reverse=True)).dns.response
    assert packet(frame(payload=bytes(raw))).dns.response_code == 3
    assert packet(frame(port=443)).dns is None
    assert packet(frame(port=443)).dns_status == "PORT443_CONTENT_UNKNOWN_POSSIBLE_DOH"
    assert packet(frame(port=853)).dns_status == "PORT853_CONTENT_UNOBSERVABLE"


def test_tcp_partial_frame_is_not_a_dns_query():
    data = frame(tcp=True)[:-1]
    # Repair IP length for a valid partial TCP segment.
    data = bytearray(data)
    data[16:18] = struct.pack("!H", len(data) - 14)
    value = packet(bytes(data))
    assert value.dns is None and value.dns_status == "DNS_TCP_STREAM_REASSEMBLY_REQUIRED"


def test_bidirectional_counts_units_flags_and_no_top40_claim():
    config = CaptureConfig(interface="lo", idle_seconds=3, active_seconds=5)
    table = FlowTable(config)
    when = utc_now()
    a = packet(frame(tcp=True), timestamp=when)
    b = packet(frame(tcp=True, reverse=True), timestamp=when + timedelta(seconds=1))
    table.add(a, "first")
    table.add(b, "second")
    table.add(b, "second")
    summary = table.expire(when + timedelta(seconds=4))[0]
    assert summary.forward_packets == summary.backward_packets == 1
    assert summary.duration_seconds == 1
    assert summary.forward_bytes == a.frame_length and summary.backward_bytes == b.frame_length
    assert summary.frame_length_mean == (a.frame_length + b.frame_length) / 2
    assert dict(summary.tcp_flag_counts)["SYN"] == 2
    assert summary.incomplete and summary.feature_status == "DIAGNOSTIC_ONLY"


def test_active_timeout_capacity_and_backwards_time():
    table = FlowTable(CaptureConfig(interface="lo", idle_seconds=30, active_seconds=1, max_flows=1))
    when = utc_now()
    table.add(packet(timestamp=when), "a")
    expired = table.add(packet(timestamp=when + timedelta(seconds=1)), "b")
    assert expired[0].close_reason == "ACTIVE_TIMEOUT"
    with pytest.raises(ValueError, match="TIME_REVERSED"):
        table.add(packet(timestamp=when), "c")
    with pytest.raises(ValueError, match="CAPACITY"):
        table.add(packet(frame(port=80), timestamp=when + timedelta(seconds=1)), "d")


@pytest.mark.parametrize("name", ["../eth0", "/sys/class/net/eth0", "x" * 16, "eth0;id"])
def test_interface_input_validation(name):
    with pytest.raises(ValidationError):
        CaptureConfig(interface=name)


def test_no_gate_can_be_opened_by_schema_or_fixture():
    assert all(
        g["inference"] == "BLOCKED"
        and g["operational_input"] == "NOT_INFERABLE"
        and g["finding_promotion"] == "BLOCKED"
        for g in model_gates().values()
    )
    assert hashlib.sha256(frame()).hexdigest() == packet().raw_frame_digest
