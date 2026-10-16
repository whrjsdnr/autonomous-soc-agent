import asyncio
import socket

import pytest
from tests.research_adapter_support import research_paths
from tests.total_monitoring_support import dns_packet
from tests.unit.streaming_network.test_transport import stat

from soc_agent.security_ai.operational.network_capture import helper_transport
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
from soc_agent.security_ai.research.live_input import timestamp_ns
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, "rate", "drop", "unknown", "private_name"])
async def test_total_unix_fixture_dns_and_closed_fail_closed(tmp_path, monkeypatch, failure):
    # Only peer/raw-socket attestation is mocked. No capture or test traffic exists.
    monkeypatch.setattr(helper_transport, "validate_peer", lambda *a, **kw: None)
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    assert (await owner.start())["listener_ready"]
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.connect(owner.session.socket_address)
    client.sendall(stat(owner.session, 1, 0, kind="READY").model_dump_json().encode())
    for _ in range(200):
        if owner.state == "LIVE_COLLECTION":
            break
        await asyncio.sleep(0.01)
    try:
        p = dns_packet(owner, 0)
        q = (
            p.dns.model_copy(update={"query_name": "private.example"})
            if failure == "private_name"
            else p.dns
        )
        p = p.model_copy(
            update={
                "timestamp_origin": "KERNEL_SO_TIMESTAMPNS",
                "capture_timestamp_ns": timestamp_ns(p),
                "dns": q,
            }
        )
        client.sendall(stat(owner.session, 2, 1).model_dump_json().encode())
        client.sendall(
            StreamMessage(
                kind="PACKET",
                session_id=owner.session.session_id,
                sequence=1,
                counter_sequence=2,
                packet=p,
            )
            .model_dump_json()
            .encode()
        )
        client.sendall(
            StreamMessage(
                kind="CLOSED",
                session_id=owner.session.session_id,
                counter_sequence=3,
                kernel_packets=0,
                kernel_packets_total=1,
                capture_drops=1 if failure == "drop" else 0,
                capture_drops_total=1 if failure == "drop" else 0,
                counter_status="COUNTER_UNAVAILABLE"
                if failure == "unknown"
                else "CAPTURE_DROPS_DETECTED"
                if failure == "drop"
                else "COUNTER_VERIFIED",
                received_frames=1,
                sent_packets=1,
                elapsed_seconds=1,
                error="STREAM_RATE_BUDGET_EXCEEDED" if failure == "rate" else None,
            )
            .model_dump_json()
            .encode()
        )
        await asyncio.wait_for(owner.task, 5)
        if failure is None:
            assert owner.state == "STOPPED", owner.last_error
            assert owner.capture.completion_verified()
            assert owner.snapshot()["dns"]["counts"]["QUERY"] == 1
        else:
            assert owner.state == "ERROR"
            assert owner.metrics["finalization"] == "BLOCKED"
            assert not owner.capture.completion_verified()
        assert owner.metrics["inference_count"] == 0  # SHUTDOWN remains ineligible.
        assert owner.snapshot()["collectors"]["dns9_ai"].startswith("BLOCKED")
        assert owner.store.runtime.verify_audit()
    finally:
        client.close()
        await owner.stop(abort=True)
