"""Actual ingress C, synthetic packets, userspace helper mocks; never a Kernel verifier."""

import ctypes
import struct
import subprocess
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import pytest
from tests.unit.live_network.test_parity import wire

from soc_agent.continuous.native import build as native_build
from soc_agent.continuous.tcx_producer import decode
from soc_agent.security_ai.ebpf.ring import ABI


@pytest.fixture(scope="module")
def ingress(tmp_path_factory):
    directory = tmp_path_factory.mktemp("host-ingress")
    root = Path(native_build.__file__).parent
    fixture = Path(__file__).parents[2] / "fixtures/continuous/kernel_harness.c"
    target = directory / "ingress.so"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-shared",
            "-fPIC",
            "-Wno-unknown-pragmas",
            "-I" + str(root),
            "-I" + str(root.parents[1] / "security_ai/ebpf"),
            str(fixture),
            "-o",
            str(target),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    lib = ctypes.CDLL(str(target))
    lib.run_packet.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint,
    ]
    lib.run_packet.restype = ctypes.c_int
    lib.copy_counters.argtypes = [ctypes.c_void_p]
    return lib


def packet(options):
    if not options:
        return wire()
    body = bytearray(wire())
    body[14] = 0x4F
    body[16:18] = struct.pack("!H", 80)
    body = body[:34] + b"\0" * 40 + body[34:]
    # Two VLAN tags plus maximum IPv4 IHL exercise the failing variable offsets.
    return body[:12] + b"\x81\x00\0\0\x88\xa8\0\0\x08\x00" + body[14:]


@pytest.mark.parametrize("options", [False, True])
def test_real_ingress_metadata_and_temporary_header_erased(ingress, options):
    body = bytes(packet(options))
    output = ctypes.create_string_buffer(ABI.size)
    assert ingress.run_packet(body, len(body), 0, output, ABI.size) == 1
    event = decode(
        output.raw,
        namespace="net:[1]",
        session=uuid5(NAMESPACE_URL, "7"),
        program="a" * 64,
        sequence=1,
    )
    assert (event.source_port, event.destination_port, event.protocol) == (1000, 2000, "tcp")
    assert event.frame_length == len(body)
    counts = (ctypes.c_uint64 * 7)()
    ingress.copy_counters(counts)
    assert list(counts) == [1, 1, 0, 0, 0, 0, 0]


@pytest.mark.parametrize(
    "failure,expected", [(1, [1, 0, 0, 0, 1, 0, 0]), (2, [1, 0, 1, 0, 0, 0, 0])]
)
def test_copy_and_ring_failure_erase_header_and_account_loss(ingress, failure, expected):
    body = bytes(packet(True))
    output = ctypes.create_string_buffer(ABI.size)
    assert ingress.run_packet(body, len(body), failure, output, ABI.size) == 0
    counts = (ctypes.c_uint64 * 7)()
    ingress.copy_counters(counts)
    assert list(counts) == expected


def test_actual_c_provider_preserves_primary_errno_after_cleanup(tmp_path):
    root = Path(native_build.__file__).parent
    fixture = Path(__file__).parents[2] / "fixtures/continuous/provider_error_harness.c"
    target = tmp_path / "provider-error.so"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-shared",
            "-fPIC",
            "-I" + str(root),
            "-I" + str(root.parents[1] / "security_ai/ebpf"),
            str(fixture),
            "-lbpf",
            "-o",
            str(target),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    lib = ctypes.CDLL(str(target))
    import errno

    assert lib.open_failure_errno() == errno.EACCES


@pytest.mark.parametrize("ipv6,tcp", [(False, False), (True, False), (True, True)])
def test_other_protocols_preserve_metadata_and_erase_header(ingress, ipv6, tcp):
    body = wire(length=60 if ipv6 else 40, ipv6=ipv6, tcp=tcp)
    output = ctypes.create_string_buffer(ABI.size)
    assert ingress.run_packet(body, len(body), 0, output, ABI.size) == 1
    event = decode(
        output.raw,
        namespace="net:[1]",
        session=uuid5(NAMESPACE_URL, "7"),
        program="a" * 64,
        sequence=1,
    )
    assert event.protocol == ("tcp" if tcp else "udp")
    assert event.source.version == (6 if ipv6 else 4)
    assert (event.source_port, event.destination_port) == (1000, 2000)
