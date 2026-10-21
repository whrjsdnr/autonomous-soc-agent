"""Known file-only checksum models; never proof of historical Native packet bytes."""

import json
import os
import struct
from pathlib import Path

import pytest
from tests.integration.zeek_attestation.test_c3_dns import dns_frames, tcp_segment
from tests.zeek_collector_support import checksum
from tests.zeek_producer_support import write_pcap

from soc_agent.security_ai.collectors.live_contract import new_plan
from soc_agent.security_ai.collectors.live_process import StreamProcess


def checksum_values(frame: bytes) -> dict:
    """Diagnostic for this Ethernet/IPv4/unfragmented file fixture, no repair/export."""
    unknown = dict(
        status="UNKNOWN", actual_ipv4=None, actual_transport=None, computed_transport=None
    )
    if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
        return unknown
    ihl = (frame[14] & 15) * 4
    length = int.from_bytes(frame[16:18], "big")
    protocol = frame[23]
    if (
        ihl < 20
        or length < ihl
        or len(frame) < 14 + length
        or int.from_bytes(frame[20:22], "big") & 0x3FFF
    ):
        return unknown
    segment = bytearray(frame[14 + ihl : 14 + length])
    offset = 6 if protocol == 17 else 16 if protocol == 6 else None
    if offset is None or len(segment) < (8 if protocol == 17 else 20):
        return unknown
    stored = int.from_bytes(segment[offset : offset + 2], "big")
    segment[offset : offset + 2] = b"\0\0"
    pseudo = frame[26:34] + struct.pack("!BBH", 0, protocol, len(segment))
    expected = checksum(pseudo + segment)
    if protocol == 17 and expected == 0:
        expected = 65535
    return dict(
        status="NOT_PRESENT_IPV4_UDP"
        if protocol == 17 and stored == 0
        else "MATCH"
        if stored == expected
        else "MISMATCH",
        actual_ipv4=int.from_bytes(frame[24:26], "big"),
        ipv4_checksum_valid=checksum(frame[14 : 14 + ihl]) == 0,
        actual_transport=stored,
        computed_transport=expected,
        folded_pseudo_header=checksum(pseudo) ^ 65535,
        capture_direction="NOT_IN_CLASSIC_PCAP",
        kernel_checksum_state="NOT_IN_CLASSIC_PCAP",
        actual_length=len(frame),
        ip_length=length,
        ipv4_ihl=ihl,
    )


def modeled_frame(frame: bytes, mode: str) -> bytes:
    value = checksum_values(frame)
    assert value["status"] != "UNKNOWN" and value["ipv4_checksum_valid"]
    result = bytearray(frame)
    offset = 14 + value["ipv4_ihl"] + (6 if frame[23] == 17 else 16)
    # The seed is a constructed CHECKSUM_PARTIAL model, not a claim about any
    # Native skb. A corrupt completed packet and a partial seed both look bad
    # to a byte-only verifier; evidence of offload state is needed to distinguish.
    stored = (
        value["folded_pseudo_header"] if mode == "partial_seed" else value["computed_transport"]
    )
    result[offset : offset + 2] = struct.pack("!H", stored)
    if mode == "corrupt":
        result[offset] ^= 1  # Actual corruption of a completed fixture checksum.
    return bytes(result)


@pytest.mark.parametrize("transport", ["udp", "tcp"])
@pytest.mark.parametrize("mode", ["valid", "partial_seed", "corrupt"])
def test_pinned_zeek_distinguishes_validity_but_not_cause(tmp_path, transport, mode):
    q, r = dns_frames(tmp_path / "base.pcap")
    frames = [q, r]
    if transport == "tcp":
        qbody, rbody = q[42:], r[42:]
        qbody, rbody = struct.pack("!H", len(qbody)) + qbody, struct.pack("!H", len(rbody)) + rbody
        frames = [
            tcp_segment(q),
            tcp_segment(q, reverse=True, seq=500, ack=101, flags=18),
            tcp_segment(q, seq=101, ack=501, flags=16),
            tcp_segment(q, seq=101, ack=501, flags=24, payload=qbody),
            tcp_segment(q, reverse=True, seq=501, ack=101 + len(qbody), flags=24, payload=rbody),
            tcp_segment(q, seq=101 + len(qbody), ack=501 + len(rbody), flags=17),
            tcp_segment(q, reverse=True, seq=501 + len(rbody), ack=102 + len(qbody), flags=17),
            tcp_segment(q, seq=102 + len(qbody), ack=502 + len(rbody), flags=16),
        ]
    frames = [modeled_frame(frame, mode) for frame in frames]
    values = [checksum_values(frame) for frame in frames]
    assert all(value["ipv4_checksum_valid"] for value in values)
    assert all(value["status"] == ("MATCH" if mode == "valid" else "MISMATCH") for value in values)
    pcap = tmp_path / "input.pcap"
    write_pcap(
        pcap, [(1800000000000000000 + i * 50_000_000, frame) for i, frame in enumerate(frames)]
    )
    plan = new_plan()
    StreamProcess(tmp_path, plan, fixture=pcap).run()
    rows = [json.loads(line) for line in (tmp_path / "stream.jsonl").read_text().splitlines()]
    closed = rows[-1]
    assert closed["kind"] == "closed"
    stages = closed["data"]["dns_diagnostics"]
    if mode == "valid":
        assert stages["query_parsed"] == stages["response_parsed"] == 1
        assert stages["transaction_matched"] == 1 and stages["transport_checksum_rejected"] == 0
    else:
        assert stages["query_parsed"] == stages["response_parsed"] == 0
        assert stages["transport_checksum_rejected"] == len(frames)
    receipt = json.loads((tmp_path / "exit.json").read_text())
    assert (
        receipt["protocol_finalized"]
        and receipt["cleanup_verified"]
        and not receipt["native_capture"]
    )
    if os.getenv("SOC_CHECKSUM_EVIDENCE"):
        out = Path(os.environ["SOC_CHECKSUM_EVIDENCE"])
        (out / f"{transport}-{mode}.json").write_text(
            json.dumps(
                dict(
                    source="GENERATED_PCAP_NOT_NATIVE_EVIDENCE",
                    mode=mode,
                    transport=transport,
                    checksums=values,
                    dns_stages=stages,
                    closed_observed=True,
                    root_cause_of_historical_native="UNKNOWN_NO_ORIGINAL_BYTES_OR_AUX_STATUS",
                ),
                indent=2,
            )
            + "\n"
        )


def test_truncated_vlan_and_fragmented_fixture_are_unknown(tmp_path):
    # The diagnostic has a narrow explicit scope; it never guesses offsets.
    assert checksum_values(bytes(20))["status"] == "UNKNOWN"
    packet = b"\0" * 12 + b"\x81\x00" + bytes(60)
    assert checksum_values(packet)["status"] == "UNKNOWN"
    query, _ = dns_frames(tmp_path / "base.pcap")
    assert checksum_values(query)["status"] == "NOT_PRESENT_IPV4_UDP"
    assert checksum_values(query[:-1])["status"] == "UNKNOWN"
    fragmented = bytearray(query)
    fragmented[20:22] = struct.pack("!H", 0x2000)
    assert checksum_values(bytes(fragmented))["status"] == "UNKNOWN"
