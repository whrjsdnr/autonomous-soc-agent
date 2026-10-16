import asyncio
import json
import socket

import pytest
from tests.research_adapter_support import research_paths
from tests.total_monitoring_support import total_source
from tests.unit.streaming_network.test_transport import stat

from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_service import StreamingMonitoring
from soc_agent.security_ai.research.total_export import export


@pytest.mark.asyncio
async def test_total_bounded_unix_replay_to_actual_models_is_explicit_fixture(
    tmp_path, monkeypatch
):
    from soc_agent.security_ai.operational.network_capture import helper_transport
    from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
    from soc_agent.security_ai.operational.network_capture.total_transport import TotalCapture
    from soc_agent.security_ai.research.live_input import timestamp_ns

    monkeypatch.setattr(helper_transport, "validate_peer", lambda *a, **kw: None)
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    observed = []

    async def source():
        capture = TotalCapture(owner.directory, owner.session)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        client.connect(owner.session.socket_address)
        client.sendall(stat(owner.session, 1, 0, kind="READY").model_dump_json().encode())
        await asyncio.to_thread(capture.handshake)
        capture.start_reader()
        packets = [p async for p in total_source(owner)]
        try:
            for n, packet in enumerate(packets, 1):
                packet = packet.model_copy(
                    update={
                        "timestamp_origin": "KERNEL_SO_TIMESTAMPNS",
                        "capture_timestamp_ns": timestamp_ns(packet),
                    }
                )
                client.sendall(stat(owner.session, n + 1, n).model_dump_json().encode())
                client.sendall(
                    StreamMessage(
                        kind="PACKET",
                        session_id=owner.session.session_id,
                        sequence=n,
                        counter_sequence=n + 1,
                        packet=packet,
                    )
                    .model_dump_json()
                    .encode()
                )
            n = len(packets)
            client.sendall(
                StreamMessage(
                    kind="CLOSED",
                    session_id=owner.session.session_id,
                    counter_sequence=n + 2,
                    kernel_packets=0,
                    kernel_packets_total=n,
                    capture_drops=0,
                    capture_drops_total=0,
                    counter_status="COUNTER_VERIFIED",
                    received_frames=n,
                    sent_packets=n,
                    elapsed_seconds=1,
                )
                .model_dump_json()
                .encode()
            )
            while capture.terminal is None or not capture.packets.empty():
                packet = await asyncio.to_thread(capture.receive)
                if packet is None:
                    await asyncio.sleep(0.01)
                    continue
                observed.append(capture.last_seal[0])
                # Peer attestation is MOCKED. Never authorize these as Native model input.
                yield packet.model_copy(
                    update={"timestamp_origin": "FIXTURE", "capture_timestamp_ns": None}
                )
            assert capture.completion_verified()
        finally:
            client.close()
            capture.close()

    await owner.start_fixture(source())
    await asyncio.wait_for(owner.task, 30)
    assert observed == [1, 2, 3, 4, 5, 6]
    assert owner.metrics["inference_count"] == 4, owner.last_error
    assert owner.snapshot()["dns"]["counts"]["MATCHED_RESPONSE"] == 1
    assert owner.snapshot()["input_origin"] == "FIXTURE"


@pytest.mark.asyncio
async def test_total_fixture_actual_models_dns_investigation_export_and_recovery(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    await owner.start_fixture(total_source(owner))
    await owner.task
    snapshot = owner.snapshot()
    assert snapshot["network"]["finalization"] == "VERIFIED", owner.last_error
    assert snapshot["dns"]["counts"]["MATCHED_RESPONSE"] == 1
    assert snapshot["dns"]["dns9_inference"] == "BLOCKED"
    assert snapshot["network"]["inference_count"] == 4
    assert all(
        r["investigation"]["status"] == "ASSESSED_READ_ONLY"
        for r in snapshot["research"]["records"]
    )
    assert {r["receipt"]["profile"] for r in snapshot["research"]["records"]} == {"quality", "edge"}
    assert all(r["receipt"]["origin"] == "FIXTURE" for r in snapshot["research"]["records"])
    for format in ("json", "markdown"):
        result = export(owner, tmp_path / format, format)
        assert result["status"] == "EXPORTED_LOCAL_ONLY"
        with pytest.raises(FileExistsError):
            export(owner, tmp_path / format, format)
    data = json.loads((tmp_path / "json").read_text())
    assert data["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
    assert all(r["investigation_summary"]["checkpoint_restored"] for r in data["records"])
    assert "192.0.2." not in json.dumps(data) and "query_name" not in json.dumps(data)
    before = [digest(r["receipt"]) for r in snapshot["research"]["records"]]
    restored = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    recovery = await restored.restore_latest()
    assert recovery["network"]["inference_count"] == 0
    assert not recovery["collection_live"]
    assert [digest(r["receipt"]) for r in recovery["research"]["records"]] == before
    assert recovery["dns"]["counts"]["MATCHED_RESPONSE"] == 1
