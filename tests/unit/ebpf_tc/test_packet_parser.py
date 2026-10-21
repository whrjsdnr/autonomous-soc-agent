"""TCX fixed-destination reads versus unchanged Legacy parser; no Kernel load."""

import ctypes
import struct
import subprocess
from pathlib import Path

import pytest
from tests.zeek_producer_support import valid_wire

from soc_agent.security_ai.ebpf_tc.build import ROOT


@pytest.fixture(scope="module")
def parse(tmp_path_factory):
    output = tmp_path_factory.mktemp("tcx-packet-reader") / "parser.so"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-pragmas",
            "-shared",
            "-fPIC",
            "-I" + str(ROOT),
            str(Path(__file__).with_name("packet_parser_fixture.c")),
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
    )
    library = ctypes.CDLL(str(output))
    library.fixture_parse.argtypes = (
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
    )
    library.fixture_parse.restype = ctypes.c_int

    def run(body, *, tcx=True, wire=None, fail_offset=-1):
        packet = ctypes.create_string_buffer(body)
        event = ctypes.create_string_buffer(80)
        rc = library.fixture_parse(
            packet,
            len(body),
            len(body) if wire is None else wire,
            tcx,
            fail_offset,
            event,
        )
        return rc, event.raw

    return run


def parity(parse, frame, expected):
    actual = parse(bytes(frame))
    original = parse(bytes(frame), tcx=False)
    assert actual[0] == original[0] == expected
    if expected == 0:
        assert actual[1] == original[1] and len(actual[1]) == 80
    return actual


@pytest.mark.parametrize("ihl", range(5, 16))
@pytest.mark.parametrize("tcp", [True, False])
@pytest.mark.parametrize("vlans", [0, 1, 2])
def test_ipv4_options_and_network_order_match_legacy(parse, ihl, tcp, vlans):
    frame = bytearray(valid_wire(tcp=tcp))
    added = (ihl - 5) * 4
    frame[34:34] = bytes(added)
    frame[14] = 0x40 | ihl
    frame[16:18] = struct.pack("!H", len(frame) - 14)
    for _ in range(vlans):
        frame = frame[:12] + b"\x81\x00\x00\x01" + frame[12:]
    parity(parse, frame, 0)


@pytest.mark.parametrize("tcp", [True, False])
@pytest.mark.parametrize("vlans", [0, 1, 2, 3])
def test_ipv6_tcp_udp_and_vlan_limit(parse, tcp, vlans):
    frame = valid_wire(tcp=tcp, ipv6=True, length=60)
    for _ in range(vlans):
        frame = frame[:12] + b"\x81\x00\x00\x01" + frame[12:]
    parity(parse, frame, 1 if vlans == 3 else 0)


@pytest.mark.parametrize(
    "case", ["fragment", "extension", "ihl", "total", "tcp", "udp", "short", "jumbo"]
)
def test_unsupported_and_malformed_remain_distinct(parse, case):
    frame = bytearray(
        valid_wire(
            tcp=case != "udp",
            ipv6=case in {"extension", "jumbo"},
            length=60 if case in {"extension", "jumbo"} else 40,
        )
    )
    if case == "fragment":
        frame[20:22] = b"\x20\x00"
    elif case == "extension":
        frame[20] = 44
    elif case == "ihl":
        frame[14] = 0x44
    elif case == "total":
        frame[16:18] = b"\xff\xff"
    elif case == "tcp":
        frame[46] = 0xF0
    elif case == "udp":
        frame[38:40] = b"\x00\x01"
    elif case == "short":
        frame = frame[:20]
    else:
        frame[18:20] = b"\x00\x00"
    parity(parse, frame, 1 if case in {"fragment", "extension", "jumbo"} else 2)


def test_truncated_helper_failure_and_existing_128_byte_window(parse):
    frame = valid_wire()
    for size in range(len(frame)):
        assert parse(frame[:size], wire=len(frame))[0] == 2
    for offset in (0, 14, 34):
        assert parse(frame, fail_offset=offset)[0] == 2
    # Trailing payload is ignored; the existing parser window is not expanded.
    parity(parse, valid_wire(length=200), 0)
    # Full packet present, but IPv4 options + TCP options exceed the old
    # 128-byte metadata inspection window. Do not silently broaden support.
    frame = bytearray(valid_wire(length=120))
    frame[34:34] = bytes(40)
    frame[14] = 0x4F
    frame[16:18] = struct.pack("!H", len(frame) - 14)
    frame[86] = 0xF0
    for _ in range(2):
        frame = frame[:12] + b"\x81\x00\x00\x01" + frame[12:]
    parity(parse, frame, 2)
