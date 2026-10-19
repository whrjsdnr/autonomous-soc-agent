"""Saved comparison evidence and synthetic DNS wire data; no capture or queries."""

import json
import struct
from pathlib import Path
from uuid import uuid4

import pytest
from tests.unit.network_capture.test_packets import frame, packet
from tests.unit.streaming_network.test_timestamp_order import observed

from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
from soc_agent.security_ai.operational.network_capture.streaming_flow import (
    PacketTimeReversed,
    StreamingFlows,
)
from soc_agent.security_ai.research.live_input import timestamp_ns
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.total_dns import DNSDiagnostics


def test_saved_native_comparison_evidence_is_internally_bound():
    root = Path(__file__).resolve().parents[3]
    evidence = json.loads(
        (root / "docs/linux-soc-v1/total-native-timestamp-dns-evidence.json").read_text()
    )
    record = evidence["record"]
    assert evidence["record_digest"] == digest(record)
    context = record["time_context"]
    assert context["previous_event_ns"] - context["rejected_event_ns"] == 11
    assert context["regression_ns"] == 11
    assert context["packet_sequence"] == context["helper_packet_sequence"] == 18
    assert context["ordering_scope"] == "GLOBAL"
    assert context["root_cause"] == "UNKNOWN"
    assert record["validation"]["database_integrity"] == "PASS_7_DATABASES"
    assert record["validation"]["audit_records"] == 8
    assert record["classification"]["dns_primary"] == "EARLY_ABORT"
    assert record["classification"]["dns_actual_traffic"] == "UNKNOWN"
    assert record["classification"]["native_total_e2e"] == "BLOCKED"
    assert record["gates"]["dns9"] == "BLOCKED"
    assert record["counts"]["controller_accepted_packets"] == 17
    assert record["counts"]["inference_receipts"] == 0
    changed = json.loads(json.dumps(record))
    changed["time_context"]["rejected_event_ns"] += 11
    assert digest(changed) != evidence["record_digest"]


def test_exact_native_pair_survives_mock_recvmsg_json_and_global_cross_flow_check():
    # Values are saved comparison operands, not reconstructed native packets.
    first = observed(1792367059623629397)
    other = observed(1792367059623629386).model_copy(update={"destination_port": 9000})
    assert first.timestamp == other.timestamp  # datetime alone would hide 11 ns.
    table = StreamingFlows()
    assert table.table.key(first) != table.table.key(other)
    table.add(first, uuid4())
    message = StreamMessage(kind="PACKET", session_id=uuid4(), sequence=2, packet=other)
    restored = StreamMessage.model_validate_json(message.model_dump_json()).packet
    assert timestamp_ns(restored) == 1792367059623629386
    with pytest.raises(PacketTimeReversed) as failure:
        table.add(restored, uuid4())
    assert failure.value.scope == "GLOBAL"  # Does not prove same-flow time reversal.
    assert failure.value.previous_ns - failure.value.rejected_ns == 11
    assert table.observed == 1
    table.close("RESTART_GAP")
    assert not table.packets and table.bytes == 0


@pytest.mark.parametrize("tcp", [False, True])
@pytest.mark.parametrize("response", [False, True])
def test_wsl_resolver_endpoint_wire_format_is_not_rejected(tcp, response):
    # Replace fixture addresses with the documented WSL resolver and a loopback client.
    raw = bytearray(frame(tcp=tcp, reverse=response))
    origin, destination = (
        ("10.255.255.254", "127.0.0.1")
        if response
        else (
            "127.0.0.1",
            "10.255.255.254",
        )
    )
    raw[26:30] = bytes(map(int, origin.split(".")))
    raw[30:34] = bytes(map(int, destination.split(".")))
    if response:
        dns_start = 14 + 20 + (22 if tcp else 8)
        raw[dns_start + 2 : dns_start + 4] = struct.pack("!H", 0x8180)
    value = packet(bytes(raw))
    assert value.dns is not None and value.dns.response == response
    assert value.dns.query_name is None
    diagnostics = DNSDiagnostics(uuid4())
    event = diagnostics.observe(value, 1)[0]
    assert event["status"] == ("UNMATCHED_RESPONSE" if response else "QUERY")
    assert diagnostics.snapshot()["dns9_inference"] == "BLOCKED"
    assert "Private123" not in json.dumps(diagnostics.snapshot())


def test_tcp_coalescing_and_encrypted_ports_are_diagnostics_not_dns9_features():
    raw = bytearray(frame(tcp=True))
    # Two complete length-prefixed messages in one segment require a stream parser.
    raw += raw[54:]
    raw[16:18] = struct.pack("!H", len(raw) - 14)
    value = packet(bytes(raw))
    assert value.dns is None
    assert value.dns_status == "DNS_TCP_STREAM_REASSEMBLY_REQUIRED"
    diagnostics = DNSDiagnostics(uuid4())
    assert diagnostics.observe(value, 1)[0]["status"] == "PARSE_FAILURE"
    for sequence, port in enumerate((443, 853), 2):
        event = diagnostics.observe(packet(frame(port=port)), sequence)[0]
        assert event["status"] == "ENCRYPTED_VISIBILITY_UNKNOWN"
    assert diagnostics.snapshot()["dns9_inference"] == "BLOCKED"
