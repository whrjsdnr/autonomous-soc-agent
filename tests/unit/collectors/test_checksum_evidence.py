"""No socket creation, sudo, capture, BPF, or DNS queries in these tests."""

import struct

import pytest

from soc_agent.security_ai.collectors.checksum_evidence import (
    FILTER,
    capture,
    describe,
    folded_checksum,
)


def packet(protocol=17, partial=False, ihl=20):
    # Fixed test DNS query; memory only. TCP includes length-prefixed DNS.
    dns = struct.pack("!6H", 0xC201, 0x100, 1, 0, 0, 0) + b"\1x\0\0\1\0\1"
    transport = (
        struct.pack("!HHHH", 40000, 53, 8 + len(dns), 0) + dns
        if protocol == 17
        else struct.pack("!HHIIBBHHH", 40000, 53, 1, 1, 0x50, 0x18, 1024, 0, 0)
        + struct.pack("!H", len(dns))
        + dns
    )
    pseudo = b"\x7f\0\0\1\x7f\0\0\x35" + struct.pack("!BBH", 0, protocol, len(transport))
    offset = 6 if protocol == 17 else 16
    value = folded_checksum(pseudo) ^ 65535 if partial else folded_checksum(pseudo + transport)
    transport = transport[:offset] + struct.pack("!H", value) + transport[offset + 2 :]
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | (ihl // 4),
        0,
        ihl + len(transport),
        123,
        0,
        64,
        protocol,
        0,
        b"\x7f\0\0\1",
        b"\x7f\0\0\x35",
    ) + bytes(ihl - 20)
    header = header[:10] + struct.pack("!H", folded_checksum(header)) + header[12:]
    return header + transport


def aux(body, status=1):
    return struct.pack("=IIIHHHH", status, len(body), len(body), 0, 0, 0, 0)


def filtered(body):
    # Interpret the tiny fixed cBPF instruction set without loading it in Kernel.
    a = x = pc = 0
    for _ in range(32):
        code, jt, jf, k = FILTER[pc]
        pc += 1
        if code == 6:
            return k
        if code in {0x20, 0x28, 0x30, 0x48}:
            size = {0x20: 4, 0x28: 2, 0x30: 1, 0x48: 2}[code]
            start = k + (x if code == 0x48 else 0)
            if start + size > len(body):
                return 0
            a = int.from_bytes(body[start : start + size], "big")
        elif code == 0xB1:
            x = (body[k] & 15) * 4
        elif code == 0x15:
            pc += jt if a == k else jf
        elif code == 0x45:
            pc += jt if a & k else jf
        else:
            raise AssertionError(code)
    raise AssertionError("filter did not terminate")


@pytest.mark.parametrize("protocol", [6, 17])
@pytest.mark.parametrize("partial", [False, True])
def test_checksum_and_kernel_flags_are_same_record(protocol, partial):
    body = packet(protocol, partial)
    record = describe(body, aux(body, 1 | (8 if partial else 128)), 4, 123456)
    assert record["checksum_result"] == ("MISMATCH" if partial else "MATCH")
    assert record["checksum_partial"] is partial
    assert record["ipv4_checksum"] == record["recomputed_ipv4_checksum"]
    assert record["dns_transaction_id"] == 0xC201
    assert record["timestamp_ns"] == 123456
    assert record["checksum_complete_vs_unnecessary"].startswith("UNKNOWN")
    assert "payload" not in record
    assert filtered(body) == 512


@pytest.mark.parametrize("protocol", [6, 17])
def test_filter_exact_endpoint_pair_and_options(protocol):
    body = packet(protocol, ihl=60)
    assert filtered(body) == 512
    assert describe(body, aux(body), 0, 0)["checksum_result"] == "MATCH"
    reverse = (
        body[:12] + body[16:20] + body[12:16] + body[20:60] + body[62:64] + body[60:62] + body[64:]
    )
    assert filtered(reverse) == 512
    for offset, value in (
        (12, b"\x08\x08\x08\x08"),
        (16, b"\x7f\0\0\2"),
        (62, b"\x01\xbb"),
        (6, b"\x20\0"),
        (9, b"\x01"),
    ):
        assert filtered(body[:offset] + value + body[offset + len(value) :]) == 0


def test_truncation_and_missing_aux_never_produce_valid_checksum():
    body = packet()
    assert describe(body[:25], aux(body), 0, 0)["checksum_result"] == "UNKNOWN"
    with pytest.raises(ValueError, match="AUXILIARY"):
        describe(body, b"", 0, 0)
    record = describe(body, aux(body, 257), 0, 0)
    assert record["gso_tcp"]
    assert not record["checksum_partial"]


def test_capture_rejects_unprivileged_entry_before_socket(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="TRUSTED_ENTRY"):
        capture(1000, 1000)


def test_bounded_capture_closes_fd_and_reports_socket_drops(monkeypatch):
    import io

    from soc_agent.security_ai.collectors import checksum_evidence as module

    body = packet()
    events = []
    identity = [0]

    class Channel:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            events.append("close")

        def setsockopt(self, *args):
            events.append("option")

        def bind(self, address):
            assert address == ("lo", 0x0800)
            events.append("bind")

        def settimeout(self, seconds):
            assert 0 < seconds <= 10

        def recvmsg(self, size, control):
            assert identity[0] == 1000 and size == 512
            if "received" in events:
                raise TimeoutError
            events.append("received")
            return (
                body,
                [(263, 8, aux(body)), (1, 35, struct.pack("=qq", 10, 20))],
                0,
                ("lo", 2048, 0, 772, b""),
            )

        def getsockopt(self, *args):
            return struct.pack("=II", 1, 2)

    monkeypatch.setattr(module, "restrict_process", lambda: events.append("process_restricted"))
    monkeypatch.setattr(module.socket, "socket", lambda *args: Channel())
    monkeypatch.setattr(module, "attach_filter", lambda channel: events.append("locked_filter"))
    monkeypatch.setattr(module.socket, "if_nametoindex", lambda name: 1)
    monkeypatch.setattr(module.os, "readlink", lambda name: module.NAMESPACE)
    monkeypatch.setattr(module.os, "geteuid", lambda: identity[0])
    monkeypatch.setattr(module.os, "setgroups", lambda groups: events.append("clear_groups"))
    monkeypatch.setattr(module.os, "setresgid", lambda *args: events.append("drop_gid"))
    monkeypatch.setattr(module.os, "setresuid", lambda *args: identity.__setitem__(0, 1000))
    monkeypatch.setattr(
        "builtins.open",
        lambda *args: io.StringIO("CapEff:\t0\nCapPrm:\t0\nCapInh:\t0\nCapAmb:\t0\n"),
    )
    result = module.capture(1000, 1000)
    assert (
        events.index("locked_filter")
        < events.index("bind")
        < events.index("drop_gid")
        < events.index("received")
    )
    assert events[-1] == "close"
    assert result["socket_drops"] == 2
    assert result["records"][0]["timestamp_ns"] == 10000000020
    assert result["state"] == "CLOSED"


def test_trusted_image_never_installs_or_starts_collectors():
    from soc_agent.security_ai.ebpf_tc.checksum_image import ENTRY

    assert "root_main(IMAGE, 'check')" in ENTRY
    for forbidden in (
        "'install'",
        "'rollback'",
        "unified_root_main(",
        "execve(",
        "supervisor_prepare(",
    ):
        assert forbidden not in ENTRY
    assert "_candidate_policy(IMAGE, uid, gid, environment)" in ENTRY
    assert "_verify_dependencies(IMAGE)" in ENTRY
