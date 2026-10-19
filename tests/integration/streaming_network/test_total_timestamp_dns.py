"""Ordinary Unix socket with mocked peer attestation. No Native model authorization."""

import asyncio
from datetime import UTC, datetime

import pytest
from tests.integration.streaming_network.test_timestamp_order import at_ns
from tests.research_adapter_support import research_paths
from tests.total_monitoring_support import dns_packet
from tests.unit.streaming_network.test_transport import stat

from soc_agent.security_ai.operational.network_capture import helper_transport
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
@pytest.mark.parametrize("regression", [False, True])
async def test_total_sequence18_orders_before_dns_and_recovers_without_retry(
    tmp_path, monkeypatch, regression
):
    import socket

    monkeypatch.setattr(helper_transport, "validate_peer", lambda *a, **kw: None)
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    assert (await owner.start())["listener_ready"]
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.settimeout(1)
    client.connect(owner.session.socket_address)
    client.sendall(stat(owner.session, 1, 0, kind="READY").model_dump_json().encode())
    try:
        for _ in range(200):
            if owner.state == "LIVE_COLLECTION":
                break
            await asyncio.sleep(0.01)
        assert owner.state == "LIVE_COLLECTION"
        previous_ns = 1792367059623629397
        for number in range(1, 19):
            ns = previous_ns - 17 + number
            value = at_ns(owner.session, ns)
            if number == 18:
                ns = previous_ns - 11 if regression else previous_ns + 1
                seconds, nanos = divmod(ns, 10**9)
                value = dns_packet(owner, 0).model_copy(
                    update={
                        "timestamp": datetime.fromtimestamp(seconds, UTC).replace(
                            microsecond=nanos // 1000
                        ),
                        "timestamp_origin": "KERNEL_SO_TIMESTAMPNS",
                        "capture_timestamp_ns": ns,
                    }
                )
            # Deliberately a DNS-bearing rejected packet: modeled signature differs
            # from native evidence (native helper DNS queries remained zero).
            client.sendall(
                stat(owner.session, number + 1, number, dns_queries=int(number == 18))
                .model_dump_json()
                .encode()
            )
            client.sendall(
                StreamMessage(
                    kind="PACKET",
                    session_id=owner.session.session_id,
                    sequence=number,
                    counter_sequence=number + 1,
                    packet=value,
                    dns_queries=int(number == 18),
                )
                .model_dump_json()
                .encode()
            )
        # Keep cumulative DNS counts in CLOSED; the common helper defaults to 0.
        client.sendall(
            StreamMessage(
                kind="CLOSED",
                session_id=owner.session.session_id,
                counter_sequence=20,
                kernel_packets=0,
                kernel_packets_total=18,
                capture_drops=0,
                capture_drops_total=0,
                counter_status="COUNTER_VERIFIED",
                received_frames=18,
                sent_packets=18,
                elapsed_seconds=1,
                dns_queries=1,
            )
            .model_dump_json()
            .encode()
        )
        await asyncio.wait_for(owner.task, 8)
        assert owner.metrics["packet_sequence"] == 18, owner.last_error
        assert owner.capture.delivered == 18
        assert owner.dns_diagnostics.observations == 18
        snapshot = owner.snapshot()
        assert not snapshot["collection_live"]
        assert snapshot["dns"]["counts"].get("QUERY", 0) == 1
        assert snapshot["dns"]["dns9_inference"] == "BLOCKED"
        assert owner.metrics["inference_count"] == 0
        assert not list(owner.demo.directory.glob("receipt-*.json"))
        assert owner.store.queue.counts() == {}
        if regression:
            assert owner.metrics["timestamp_integrity"] == "CROSS_FLOW_NON_MONOTONIC"
            assert owner.metrics["retained_integrity_health"] == "DEGRADED"
        assert owner.state == "STOPPED", owner.last_error
        assert owner.capture.completion_verified()
        audit_head = owner.store.runtime.verify_audit()
        assert len(audit_head) == 64
        restored = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
        recovered = await restored.restore_latest()
        assert not recovered["collection_live"]
        assert recovered["network"]["inference_count"] == 0
        assert recovered["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
        assert recovered["last_error"] is None
    finally:
        client.close()
        await owner.stop(abort=True)
