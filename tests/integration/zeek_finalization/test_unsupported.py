"""Actual pinned Zeek, generated PCAP only: network=none, cap-drop=ALL, no sudo."""

import json
import struct

import pytest
from tests.zeek_collector_support import ip_checksum, pcap_fixture
from tests.zeek_producer_support import valid_wire

from soc_agent.security_ai.collectors.live_contract import new_plan
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.collectors.live_stream import Stream, decode
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.offline import OfflineZeek


def test_pinned_zeek_mixed_protocol_dns_counter_and_closed(tmp_path):
    try:
        OfflineZeek().environment()
    except (ValueError, OSError):
        pytest.skip("Pinned offline image unavailable; no install/pull/auth fallback")
    source = tmp_path / "mixed.pcap"
    pcap_fixture(source)  # Existing UDP and DNS query/response file fixture.
    body = bytearray(valid_wire(tcp=False, length=28))
    body[23] = 1  # ICMP metadata is unsupported by the canonical TCP/UDP adapter.
    body = ip_checksum(bytes(body))
    tcp = valid_wire(flags=16)
    with source.open("ab") as output:
        for second, frame in [(3, body), (4, tcp)]:
            output.write(
                struct.pack("<IIII", 1800000000 + second, 0, len(frame), len(frame)) + frame
            )
    plan = new_plan()
    runner = StreamProcess(tmp_path, plan, fixture=source)
    runner.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    stream = Stream(
        Source(session_id=plan.session_id, source_digest=plan.identity, origin="ZEEK_OFFLINE_PCAP")
    )
    for line in (tmp_path / "stream.jsonl").read_bytes().splitlines(keepends=True):
        stream.accept(decode(line))
    assert result["protocol_finalized"] and result["closed_observed"] and result["cleanup_verified"]
    assert result["error"] is None and not result["native_capture"]
    assert (
        stream.observation_count == 7 and stream.packet_count == 6 and stream.unsupported_count == 1
    )
    assert stream.dns_count >= 1 and stream.dns_stages.query_parsed >= 1
    assert stream.dns_stages.response_parsed >= 1 and stream.dns_stages.transaction_matched >= 1
    assert stream.counter_snapshot.unsupported_packet_records == 1
    assert sum(f["packet_count"] for f in stream.finalized) == 6
    assert result["capture_integrity"] == "UNVERIFIED"  # Not a Native claim.
