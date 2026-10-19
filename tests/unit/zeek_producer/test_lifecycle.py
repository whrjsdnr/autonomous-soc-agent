import json
from unittest.mock import Mock

import pytest
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.offline import file_digest
from soc_agent.security_ai.collectors.packet_input import reference
from soc_agent.security_ai.collectors.zeek import ZeekCollector


class FileRunner:
    """Explicit mock Zeek log source, never counted as an actual Zeek run."""

    def environment(self):
        return {}

    def stop(self):
        pass

    def run(self, pcap, sha, logs):
        (logs / "conn.log").write_bytes(b"")
        (logs / "dns.log").write_bytes(b"")
        (logs / "network14_packets.log").write_text(
            "".join(p.model_dump_json() + "\n" for p in reference(pcap))
        )
        from pathlib import Path

        import soc_agent.security_ai.collectors.offline as module

        return dict(
            packet_mode=True,
            packet_policy_sha256=file_digest(Path(module.__file__).with_name("network14.zeek")),
            log_sha256={p.name: file_digest(p) for p in logs.glob("*.log")},
        )


@pytest.mark.asyncio
async def test_shutdown_never_invokes_models_and_proof_tamper_blocks_recovery(tmp_path):
    p = tmp_path / "input.pcap"
    sha = golden(p, "short")
    c = ZeekCollector(tmp_path, packet_mode=True, runner=FileRunner())
    await c.prepare(pcap=p, sha256=sha)
    await c.start()
    await c.task
    s = c.snapshot()
    assert c.state == "STOPPED" and c.producer.state == "BLOCKED_NO_TIMEOUT_ELIGIBLE_FLOW"
    assert not s["research"]["records"] and s["collector"]["metrics"]["inference_count"] == 0
    # Explicit non-privileged queued-reference fixture, never a Native measurement.
    c.producer.pending = 2
    queued = c.snapshot()
    assert queued["network"]["queue_backlog"] == 2
    assert queued["network"]["inference_queue"]["depth"] == 2
    c.producer.pending = 0
    proof = c.directory / "producer-proof.json"
    value = json.loads(proof.read_text())
    value["flows"][0]["eligible"] = True
    proof.write_text(json.dumps(value))
    assert c.snapshot()["state"] == "UNKNOWN"
    fresh = ZeekCollector(tmp_path, packet_mode=True)
    with pytest.raises(ValueError, match="PROOF_AUDIT"):
        await fresh.recover()
    assert fresh.writer is None and fresh.state == "ERROR"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["WORKER_TIMEOUT_NO_RETRY", "WORKER_FAILURE_OR_BUDGET_NO_RETRY"]
)
async def test_worker_failure_durable_unknown_and_recovery_does_not_retry(
    tmp_path, monkeypatch, failure
):
    from soc_agent.security_ai.research.adapter import ResearchAdapter

    monkeypatch.setattr(ResearchAdapter, "status", lambda *a, **k: {"status": "READY"})
    calls = []

    async def fail(self, request):
        calls.append(request.invocation_id)
        return {"status": "UNKNOWN", "error": failure}

    monkeypatch.setattr(ResearchAdapter, "infer", fail)
    p = tmp_path / "input.pcap"
    sha = golden(p)
    c = ZeekCollector(tmp_path, packet_mode=True, runner=FileRunner())
    await c.prepare(pcap=p, sha256=sha)
    await c.start()
    await c.task
    assert c.producer.state == "UNKNOWN_MODEL_OR_INVESTIGATION_NO_RETRY"
    assert c.snapshot()["last_error"] == failure
    assert len(calls) == 1 and c.producer.new_inferences == 0
    fresh = ZeekCollector(tmp_path, packet_mode=True)
    await fresh.recover()
    assert len(calls) == 1 and fresh.producer.new_inferences == 0
    assert fresh.snapshot()["research"]["records"][0]["error"] == failure
    await c.stop()
    await fresh.stop()


@pytest.mark.asyncio
async def test_prepare_producer_scope_precedes_any_engine_or_model(tmp_path):
    from tests.zeek_producer_support import valid_wire, write_pcap

    p = tmp_path / "nano.pcap"
    sha = write_pcap(p, [(1800000000000000001, valid_wire())], nanosecond=True)
    runner = Mock()
    c = ZeekCollector(tmp_path, packet_mode=True, runner=runner)
    with pytest.raises(ValueError, match="PRECISION"):
        await c.prepare(pcap=p, sha256=sha)
    runner.run.assert_not_called()
    assert c.producer is None
