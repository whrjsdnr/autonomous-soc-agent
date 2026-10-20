"""Compile is real; parser execution is a host fixture, never a kernel verifier."""

import struct

import pytest
from tests.ebpf_support import parser, plan
from tests.zeek_producer_support import valid_wire

from soc_agent.security_ai.ebpf.build import compile_program
from soc_agent.security_ai.ebpf.ring import decode


@pytest.fixture
def parse(tmp_path):
    return parser(tmp_path)


def test_actual_bpf_compile_and_consumer_link_are_not_verifier(tmp_path):
    result = compile_program(tmp_path)
    body = (tmp_path / "tc.bpf.o").read_bytes()
    assert body[:4] == b"\x7fELF" and int.from_bytes(body[18:20], "little") == 247
    assert all(len(v) == 64 for v in result.values())


@pytest.mark.parametrize("tcp,ipv6", [(True, False), (False, False), (True, True), (False, True)])
@pytest.mark.parametrize("hook", [1, 2])
def test_protocol_direction_and_header_identity(parse, tcp, ipv6, hook):
    frame = valid_wire(tcp=tcp, ipv6=ipv6, length=60 if ipv6 else 40)
    rc, raw = parse(frame, hook=hook)
    assert rc == 0
    p = plan(hook="INGRESS" if hook == 1 else "EGRESS")
    e = decode(raw, p, 1)
    assert e.ip_length == (60 if ipv6 else 40) and e.source.version == (6 if ipv6 else 4)
    assert e.protocol == ("tcp" if tcp else "udp") and e.hook == p.hook
    assert e.clock == "FIXTURE_PCAP_EVENT_NS" and e.integrity == "UNVERIFIED"
    assert e.flow_identity == decode(raw, p, 1).flow_identity


@pytest.mark.parametrize("levels", [1, 2, 3])
def test_vlan_bounded_and_no_false_dedup(parse, levels):
    frame = valid_wire()
    for _ in range(levels):
        frame = frame[:12] + b"\x81\x00\x00\x01" + frame[12:]
    rc, raw = parse(frame)
    assert rc == (1 if levels == 3 else 0)
    if rc == 0:
        e = decode(raw, plan(), 1)
        assert e.ip_length == 40 and e.frame_length == 54 + 4 * levels


@pytest.mark.parametrize("case", ["fragment", "ipv6_extension", "ethertype", "jumbo"])
def test_unsupported_formats_are_not_normalized(parse, case):
    frame = bytearray(
        valid_wire(
            ipv6=case in {"ipv6_extension", "jumbo"},
            length=60 if case in {"ipv6_extension", "jumbo"} else 40,
        )
    )
    if case == "fragment":
        frame[20:22] = b"\x20\x00"
    if case == "ipv6_extension":
        frame[20] = 44
    if case == "ethertype":
        frame[12:14] = b"\x08\x06"
    if case == "jumbo":
        frame[18:20] = b"\0\0"
    assert parse(bytes(frame))[0] == 1


@pytest.mark.parametrize(
    "case", ["short", "ihl", "ip_length", "tcp_offset", "udp_length", "ipv6_length"]
)
def test_malformed_bounds(parse, case):
    frame = bytearray(
        valid_wire(
            tcp=case != "udp_length",
            ipv6=case == "ipv6_length",
            length=60 if case == "ipv6_length" else 40,
        )
    )
    if case == "short":
        frame = frame[:20]
    if case == "ihl":
        frame[14] = 0x44
    if case == "ip_length":
        frame[16:18] = struct.pack("!H", 600)
    if case == "tcp_offset":
        frame[46] = 0xF0
    if case == "udp_length":
        frame[38:40] = b"\0\1"
    if case == "ipv6_length":
        frame[18:20] = b"\xff\xff"
    assert parse(bytes(frame))[0] == 2


def test_no_kernel_mutation_or_unconditional_native_loader():
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "src/soc_agent/security_ai/ebpf"
    text = (root / "tc.bpf.c").read_text()
    assert text.count("return TC_ACT_OK;") >= 6
    assert all(word not in text for word in ["TC_ACT_SHOT", "bpf_redirect", "bpf_skb_store_bytes"])
    consumer = (root / "consumer.c").read_text()
    assert "ring_buffer__poll" in consumer
    assert not any(
        word in consumer for word in ["bpf_object__load", "bpf_tc_attach", "bpf_obj_get("]
    )
