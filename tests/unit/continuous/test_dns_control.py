"""Inert packet metadata; no DNS query, socket or model invocation."""

import pytest
from tests.unit.network_capture.test_packets import frame, packet

from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.research.isolated_dns import IsolatedDNS


def control(payload_bytes=0, port=53):
    value = packet(frame(tcp=True, port=port)).model_dump(mode="json")
    value.update(
        dns=None,
        dns_status="DNS_TCP_STREAM_REASSEMBLY_REQUIRED",
        ip_length=40 + payload_bytes,
        header_length=40,
        frame_length=54 + payload_bytes,
    )
    return PacketObservation.model_validate(value)


@pytest.mark.parametrize("flags", [2, 16, 17, 18, 4])
def test_empty_tcp_control_retains_evidence_without_false_parse_failure(flags):
    value = control().model_copy(update=dict(tcp_flags=flags))
    engine = IsolatedDNS("fixture-no-capture")
    events = engine.observe(value, 1)
    assert len(events) == 1 and events[0]["status"] == "TRANSPORT_CONTROL"
    assert events[0]["source_reference"] and events[0]["dns9_inference"] == "BLOCKED"
    assert engine.observations == 1 and engine.diagnostic_status == "HEALTHY"
    assert not engine.connections and engine.snapshot()["pending"] == 0
    assert engine.counts.get("PARSE_FAILURE", 0) == 0


def test_partial_tcp_application_data_still_fails_and_unrelated_port_is_not_dns():
    engine = IsolatedDNS("fixture-no-capture")
    assert engine.observe(control(port=18080), 1) == []
    events = engine.observe(control(payload_bytes=1), 2)
    assert events[0]["status"] == "PARSE_FAILURE"
    assert engine.diagnostic_status == "DEGRADED"
    assert engine.snapshot()["dns9_inference"] == "BLOCKED"
