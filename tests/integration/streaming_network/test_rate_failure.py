"""Authenticated-peer check is mocked; only ordinary-user Unix sockets are used."""

import asyncio
import json

import pytest
from tests.integration.streaming_network.test_shutdown import connected

from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
@pytest.mark.parametrize("counter", ["valid", "unknown", "drop", "sequence"])
async def test_rate_closed_is_rejected_but_preserved_with_audit(tmp_path, monkeypatch, counter):
    owner, client = await connected(tmp_path, monkeypatch)
    expected = {
        "valid": "STREAM_RATE_BUDGET_EXCEEDED",
        "unknown": "HELPER_CAPTURE_COUNTER_UNAVAILABLE",
        "drop": "HELPER_CAPTURE_DROPS_DETECTED",
        "sequence": "HELPER_CAPTURE_COUNTER_INTEGRITY_FAILED",
    }[counter]
    message = StreamMessage(
        kind="CLOSED",
        session_id=owner.session.session_id,
        counter_sequence=3 if counter == "sequence" else 2,
        kernel_packets=None if counter == "unknown" else 257,
        kernel_packets_total=None if counter == "unknown" else 257,
        capture_drops=1 if counter == "drop" else 0,
        capture_drops_total=1 if counter == "drop" else 0,
        counter_status="COUNTER_UNAVAILABLE"
        if counter == "unknown"
        else "CAPTURE_DROPS_DETECTED"
        if counter == "drop"
        else "COUNTER_VERIFIED",
        received_frames=257,
        sent_packets=0,
        elapsed_seconds=0.25,
        error="STREAM_RATE_BUDGET_EXCEEDED",
    )
    try:
        client.sendall(message.model_dump_json().encode())
        await asyncio.wait_for(owner.task, 5)
        assert owner.last_error == expected
        evidence = json.loads((owner.directory / "rejected-closed.json").read_text())
        assert evidence["helper_error"] == "STREAM_RATE_BUDGET_EXCEEDED"
        assert evidence["rejection_reason"] == expected
        assert evidence["received_frames"] == 257
        assert evidence["elapsed_seconds"] == 0.25
        assert evidence["counter_validation"] == ("ACCEPTED" if counter == "valid" else "REJECTED")
        assert evidence["completion_verified"] is False
        assert (owner.directory / "rejected-closed.json").stat().st_mode & 0o777 == 0o600
        assert not (owner.directory / "verified-closed.json").exists()
        assert owner.capture.terminal is None and not owner.capture.completion_verified()
        assert owner.snapshot()["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
        state = owner.store.runtime.state()["network"]
        assert state["finalization"] == "BLOCKED" and state["inference_count"] == 0
        assert state["final_counter_status"] == "UNKNOWN"
        assert state["rejected_closed_digest"] == digest(evidence)
        with owner.store.runtime.database.transaction(write=False) as c:
            aborts = [
                json.loads(row["payload"])
                for row in c.execute("SELECT payload FROM monitor_audit")
                if json.loads(row["payload"])["kind"] == "STREAM_ABORTED"
            ]
        assert aborts[-1]["details"]["error"] == expected
        assert aborts[-1]["details"]["rejected_closed_digest"] == digest(evidence)
        assert not list(owner.demo.directory.glob("receipt-*.json"))
        assert owner.store.queue.counts() == {}
        owner.store.runtime.verify_audit()
        restored = StreamingMonitoring(tmp_path, paths=owner.paths)
        snapshot = await restored.restore_latest()
        assert snapshot["last_error"] == expected
        assert snapshot["network"]["inference_count"] == 0
    finally:
        client.close()
        await owner.stop(abort=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["unknown_error", "capabilities", "write_failure"])
async def test_rejected_closed_diagnostics_never_authorize_completion(tmp_path, monkeypatch, fault):
    from soc_agent.security_ai.operational.network_capture import helper_transport

    owner, client = await connected(tmp_path, monkeypatch)
    message = StreamMessage(
        kind="CLOSED",
        session_id=owner.session.session_id,
        counter_sequence=2,
        kernel_packets=0,
        kernel_packets_total=0,
        capture_drops=0,
        capture_drops_total=0,
        counter_status="COUNTER_VERIFIED",
        received_frames=0,
        sent_packets=0,
        elapsed_seconds=0.25,
        error="untrusted private helper message"
        if fault == "unknown_error"
        else "STREAM_RATE_BUDGET_EXCEEDED",
        capabilities={"CapEff": 8192} if fault == "capabilities" else None,
    )
    original = helper_transport.write_private

    def write(path, value):
        if fault == "write_failure" and path.name == "rejected-closed.json":
            raise OSError("MOCK_ONLY")
        return original(path, value)

    monkeypatch.setattr(helper_transport, "write_private", write)
    try:
        client.sendall(message.model_dump_json().encode())
        await asyncio.wait_for(owner.task, 5)
        expected = "HELPER_READER_FAILED" if fault == "write_failure" else "HELPER_UNCLEAN_SHUTDOWN"
        assert owner.last_error == expected
        assert not owner.capture.completion_verified()
        assert not (owner.directory / "verified-closed.json").exists()
        assert owner.metrics["finalization"] == "BLOCKED"
        assert owner.store.runtime.verify_audit()
        if fault == "unknown_error":
            assert "untrusted private" not in (owner.directory / "rejected-closed.json").read_text()
    finally:
        client.close()
        await owner.stop(abort=True)
