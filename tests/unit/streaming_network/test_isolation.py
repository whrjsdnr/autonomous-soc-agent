"""Synthetic exact-ns metadata; no socket, capture, privilege or model promotion."""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.streaming_network_support import packet
from tests.total_monitoring_support import dns_packet
from tests.unit.streaming_network.test_timestamp_order import observed, request

from soc_agent.security_ai.operational.network_capture.isolated_flow import IsolatedFlows
from soc_agent.security_ai.research.isolated_dns import IsolatedDNS
from soc_agent.security_ai.research.live_input import produce


def test_disjoint_11ns_regression_does_not_expire_other_flow_and_preserves_producer():
    flows = IsolatedFlows()
    base = 1792367059623629397
    a = observed(base)
    b = observed(base - 11).model_copy(update={"destination_port": 9000})
    flows.add(a, uuid4())
    flows.add(b, uuid4())
    assert flows.last_events[0]["kind"] == "CROSS_FLOW_EVENT_TIME_NON_MONOTONIC"
    assert flows.active_count == 2
    # Even a far-future different key cannot complete A or B.
    far = observed(base + 121_000_000_000).model_copy(update={"destination_port": 8000})
    assert flows.add(far, uuid4()) == []
    a2 = observed(base + 1)
    assert flows.add(a2, uuid4()) == []
    result = flows.add(observed(base + 30_000_000_001), uuid4())[0]
    assert result.flow.close_reason == "IDLE_TIMEOUT"
    q = request(result.packets).model_copy(update={"packet_event_ids": result.identities})
    reference = produce(q)
    assert reference.values == result.values
    assert reference.values[0] > 0  # Exact 1 ns duration, not clamped datetime.
    assert reference.feature_digest
    assert flows.allowed(result.flow.flow_id)


def test_same_flow_11ns_regression_quarantines_key_for_entire_session():
    flows = IsolatedFlows()
    base = 1792367059623629397
    flows.add(observed(base), uuid4())
    assert flows.add(observed(base - 11), uuid4()) == []
    event = flows.last_events[0]
    assert event["kind"] == "FLOW_QUARANTINED" and event["regression_ns"] == 11
    assert len(event["quarantine_reference"]) == 64
    assert flows.bytes == 0
    assert not flows.add(observed(base + 120_000_000_000), uuid4())
    assert flows.last_events[0]["kind"] == "QUARANTINED_PACKET_EXCLUDED"
    assert flows.active_count == 0
    assert flows.snapshot()["quarantined_flow_keys"] == 1


@pytest.mark.parametrize("active", [False, True])
def test_same_key_timeout_and_direction_match_batch_producer(active):
    owner = SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))
    flows = IsolatedFlows()
    times = range(0, 120, 10) if active else (0, 0.5, 1)
    for i, t in enumerate(times):
        flows.add(packet(owner, t, reverse=i % 2 == 1, length=40 + i), uuid4())
    item = flows.add(packet(owner, 120 if active else 31), uuid4())[0]
    assert item.flow.close_reason == ("ACTIVE_TIMEOUT" if active else "IDLE_TIMEOUT")
    from soc_agent.security_ai.research.live_input import LiveRequest

    q = LiveRequest(
        research_mode=True,
        origin="FIXTURE",
        profile="quality",
        invocation_id=uuid4(),
        capture_session=uuid4(),
        flow_id=item.flow.flow_id,
        provenance_digest="b" * 64,
        packets=item.packets,
        packet_event_ids=item.identities,
    )
    assert produce(q).values == item.values


def test_history_memory_duplicate_and_quarantine_limits_fail_closed():
    base = 1792367059623629397
    p = observed(base)
    flows = IsolatedFlows(records=1)
    identity = uuid4()
    flows.add(p, identity)
    with pytest.raises(ValueError, match="DUPLICATE"):
        flows.add(p, identity)
    flows.add(observed(base - 11), uuid4())
    with pytest.raises(ValueError, match="HISTORY_BACKPRESSURE"):
        flows.add(p.model_copy(update={"destination_port": 9000}), uuid4())
    assert flows.snapshot()["quarantined_flow_keys"] == 1
    assert len(flows.close()) == 0
    bounded = IsolatedFlows(metadata_bytes=8192)
    with pytest.raises(ValueError, match="MEMORY_BACKPRESSURE"):
        for i in range(128):
            bounded.add(observed(base + i), uuid4())
    assert bounded.bytes <= 8192
    bounded.close("RESTART_GAP")
    assert bounded.bytes == 0


def test_dns_no_network_watermark_negative_latency_or_duplicate_matching():
    owner = SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))
    dns = IsolatedDNS(uuid4())
    dns.observe(dns_packet(owner, 1), 1)
    dns.observe(packet(owner, 1000), 2)
    assert dns.snapshot()["pending"] == 1  # Network cannot expire a DNS query.
    response = dns.observe(dns_packet(owner, 1.5, response=True), 3)
    assert response[0]["status"] == "MATCHED_RESPONSE"
    assert response[0]["latency_seconds"] == 0.5
    assert dns.observe(dns_packet(owner, 2, response=True), 4)[0]["status"] == "UNMATCHED_RESPONSE"
    dns.observe(dns_packet(owner, 3), 5)
    assert dns.observe(dns_packet(owner, 3), 6)[0]["status"] == "AMBIGUOUS_QUERY"
    assert dns.snapshot()["dns9_inference"] == "BLOCKED"


def test_dns_11ns_connection_regression_is_local_and_cannot_match_later():
    owner = SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))
    base = 1792367059623629397
    dns = IsolatedDNS(uuid4())
    q = dns_packet(owner, 0).model_copy(
        update={
            "timestamp": observed(base).timestamp,
            "timestamp_origin": "KERNEL_SO_TIMESTAMPNS",
            "capture_timestamp_ns": base,
        }
    )
    dns.observe(q, 1)
    rejected = q.model_copy(update={"capture_timestamp_ns": base - 11})
    assert dns.observe(rejected, 2)[-1]["status"] == "DNS_TIMESTAMP_QUARANTINED"
    assert dns.snapshot()["pending"] == 0
    assert dns.observe(q, 3) == []
    other = q.model_copy(update={"source_port": 40000})
    assert dns.observe(other, 4)[0]["status"] == "QUERY"
    assert dns.snapshot()["quarantined_connections"] == 1


def test_dns_budget_failure_is_explicit_bounded_and_names_remain_forbidden():
    owner = SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))
    dns = IsolatedDNS(uuid4())
    original = dns_packet(owner, 0)
    for i in range(128):
        dns.observe(original.model_copy(update={"source_port": 20000 + i}), i + 1)
    event = dns.observe(original.model_copy(update={"source_port": 30000}), 129)[-1]
    assert event["status"] == "DNS_DIAGNOSTIC_BLOCKED"
    assert len(dns.connections) == 128 and dns.snapshot()["pending"] == 0
    assert len(dns.events) <= 128
    assert dns.snapshot()["diagnostic_status"] == "DNS_DIAGNOSTIC_BLOCKED"
    with pytest.raises(ValueError, match="NAME_RETENTION_DENIED"):
        dns.observe(
            original.model_copy(
                update={"dns": original.dns.model_copy(update={"query_name": "private.example"})}
            ),
            130,
        )
