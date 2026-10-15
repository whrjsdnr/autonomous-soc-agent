"""Actual pinned local model binaries, saved PCAP; no capture/provider/OS response."""

import asyncio
import hashlib
import json
from uuid import uuid4

import pytest

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.models import Request
from soc_agent.security_ai.research.service import ResearchDemo


@pytest.mark.asyncio
async def test_actual_quality_edge_advisory_investigation_restart_and_duplicate(tmp_path):
    backend = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    before = await backend.research_status()
    assert before["inference_counts"] == {"quality": 0, "edge": 0}
    assert not (backend.directory / "network-research").exists()
    await backend.research_start()
    result = await backend.research_replay("both", 2)
    assert result["inference_counts"] == {"quality": 1, "edge": 1}
    for item in result["records"]:
        assert item["status"] == "COMPLETE"
        assert item["receipt"]["origin"] == "OFFLINE_PCAP"
        inv = item["investigation"]
        assert inv["status"] == "ASSESSED_READ_ONLY" and inv["checkpoint_restored"]
        assert inv["prompt_digests"] and inv["evidence_references"]
        assert not inv["assessment"]["incident_state"]["observations"]
        assert not inv["assessment"]["incident_state"]["hypotheses"]
        assert inv["action_policy"] == "WRITE_DENIED"
    database = backend.research_demo._store().database.path
    old = hashlib.sha256(database.read_bytes()).hexdigest()
    await backend.research_status()
    assert hashlib.sha256(database.read_bytes()).hexdigest() == old
    await backend.close()
    restored = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    assert (await restored.research_status())["demo_state"] == "STOPPED"
    await restored.research_start()
    cached = await restored.research_replay("both", 2)
    assert cached["records"] == result["records"]
    assert cached["inference_counts"] == {"quality": 1, "edge": 1}
    await restored.close()


@pytest.mark.asyncio
async def test_worker_timeout_and_unknown_not_retried(tmp_path):
    demo = ResearchDemo(tmp_path, timeout=0.1)
    await demo.start()
    result = await demo.replay("quality", 2)
    assert result["status"] == "UNKNOWN"
    assert result["record"]["error"] == "WORKER_TIMEOUT_NO_RETRY"
    again = await demo.replay("quality", 2)
    assert (
        again.get("error") == "PREVIOUS_OUTCOME_UNKNOWN_NO_RETRY"
        or again["status"] == "CACHED_NO_NEW_INFERENCE"
    )
    assert demo.snapshot()["inference_counts"]["quality"] == 0
    assert demo.snapshot()["errors"] == 1


@pytest.mark.asyncio
async def test_stop_cancels_owned_worker_and_no_external_runtime(tmp_path):
    demo = ResearchDemo(tmp_path)
    await demo.start()
    task = asyncio.create_task(demo.replay("quality", 1))
    for _ in range(300):
        if demo.adapter.process:
            break
        await asyncio.sleep(0.01)
    assert demo.adapter.process is not None
    await demo.stop()
    result = await task
    assert result["status"] == "UNKNOWN"
    assert demo.adapter.process is None
    assert not demo.started


@pytest.mark.asyncio
async def test_receipt_tampering_fails_closed(tmp_path):
    demo = ResearchDemo(tmp_path)
    await demo.start()
    await demo.replay("edge", 0)
    path = next(demo.directory.glob("receipt-*.json"))
    data = json.loads(path.read_text())
    data["receipt"]["score"] = 0.123
    path.write_text(json.dumps(data))
    state = demo.snapshot()
    assert state["status"] == "UNKNOWN" and state["inference_counts"] is None
    with pytest.raises(ValueError):
        await demo.start()


@pytest.mark.asyncio
async def test_audit_failure_no_publish_or_replay(tmp_path, monkeypatch):
    import soc_agent.security_ai.research.service as module

    demo = ResearchDemo(tmp_path)
    await demo.start()

    def fail(*a, **k):
        raise ValueError("AUDIT_FAILED")

    monkeypatch.setattr(module, "audit", fail)
    with pytest.raises(ValueError):
        await demo.replay("quality", 0)
    assert demo.adapter.process is None
    assert demo.snapshot()["status"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_worker_crash_is_unknown(tmp_path, monkeypatch):
    adapter = ResearchAdapter(tmp_path)

    class Crashed:
        returncode = 9

        async def wait(self):
            return 9

    async def crash(*a, **k):
        return Crashed()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", crash)
    result = await adapter.infer(
        Request(research_mode=True, profile="quality", flow_index=0, invocation_id=uuid4())
    )
    assert result["status"] == "UNKNOWN" and "NO_RETRY" in result["error"]


@pytest.mark.asyncio
async def test_restart_after_dispatch_before_commit_stays_unknown(tmp_path, monkeypatch):
    demo = ResearchDemo(tmp_path)
    await demo.start()

    async def interrupted(_):
        raise RuntimeError("OWNED_FIXTURE_CRASH_AFTER_DISPATCH")

    monkeypatch.setattr(demo.adapter, "infer", interrupted)
    with pytest.raises(RuntimeError):
        await demo.replay("quality", 0)
    restored = ResearchDemo(tmp_path)
    assert restored.snapshot()["errors"] == 1
    assert restored.snapshot()["unknown_attempts"]
    await restored.start()
    result = await restored.replay("quality", 0)
    assert result["error"] == "PREVIOUS_OUTCOME_UNKNOWN_NO_RETRY"


@pytest.mark.asyncio
async def test_worker_actual_owned_crash_and_concurrency(tmp_path):
    demo = ResearchDemo(tmp_path)
    await demo.start()
    task = asyncio.create_task(demo.replay("edge", 1))
    for _ in range(300):
        if demo.adapter.process:
            break
        await asyncio.sleep(0.01)
    with pytest.raises(ValueError, match="ALREADY_RUNNING"):
        await demo.replay("quality", 1)
    assert demo.adapter.process is not None
    demo.adapter.process.kill()  # Only the owned isolated model child.
    result = await task
    assert result["status"] == "UNKNOWN" and demo.adapter.process is None


@pytest.mark.asyncio
async def test_after_result_audit_failure_is_not_success_or_replayed(tmp_path, monkeypatch):
    import soc_agent.security_ai.research.service as module

    demo = ResearchDemo(tmp_path)
    await demo.start()
    original = module.audit

    def fail_completed(connection, code, **fields):
        if code == "RESEARCH_COMPLETED":
            raise ValueError("FIXTURE_AUDIT_COMMIT_FAILED")
        return original(connection, code, **fields)

    monkeypatch.setattr(module, "audit", fail_completed)
    with pytest.raises(ValueError):
        await demo.replay("edge", 0)
    assert demo.snapshot()["status"] == "UNKNOWN"
    assert demo.snapshot()["inference_counts"] is None
    with pytest.raises(ValueError):
        await demo.replay("edge", 0)
