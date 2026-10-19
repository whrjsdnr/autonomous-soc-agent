"""Actual isolated RF/LR on synthetic packets through the shared GUI backend loop."""

import asyncio
import json
import os
import time
from pathlib import Path

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import idle_source

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.worker import Worker
from soc_agent.security_ai.operational.network_capture.calibrated_policy import policy
from soc_agent.security_ai.research.models import SPECS, digest
from soc_agent.security_ai.research.session_archive import Archive
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


def test_operator_total_real_models_export_archive_and_no_orphan(tmp_path):
    available = int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0]) * 1024
    if available < 2 * 1024**3:
        pytest.skip("REAL_MODEL_VALIDATION_BLOCKED_MEMORY_HEADROOM")
    worker = Worker(GUIConfig(data_directory=tmp_path / "gui"))
    started, cpu = time.monotonic(), time.process_time()
    directory = None
    result = {}

    async def run():
        backend = worker.backend
        owner = backend.total_monitoring
        owner.paths = research_paths()
        await owner.start_fixture(idle_source(owner), policy=policy("balanced-v2"))
        await asyncio.wait_for(owner.task, 40)
        snapshot = await backend.production_status()
        assert snapshot["network"]["finalization"] == "VERIFIED"
        assert snapshot["network"]["inference_count"] == 2
        assert snapshot["network"]["queue_backlog"] == 0
        assert snapshot["dns"]["dns9_inference"] == "BLOCKED"
        assert not snapshot["collection_live"] and snapshot["input_origin"] == "FIXTURE"
        assert "research_demo" not in backend._owners and backend.model_service is None
        records = snapshot["research"]["records"]
        assert {r["receipt"]["profile"] for r in records} == {"quality", "edge"}
        for row in records:
            receipt = row["receipt"]
            assert receipt["producer_version"] == "1.1.0" and len(receipt["feature_values"]) == 14
            assert receipt["artifact_digest"] == SPECS[receipt["profile"]]["sha256"]
            assert receipt["origin"] == "FIXTURE"
            assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
        for fmt, suffix in (("json", ".json"), ("markdown", ".md")):
            exported = await backend.total_export(str(tmp_path / ("report" + suffix)), fmt)
            assert exported["status"] == "EXPORTED_LOCAL_ONLY"
        before = [digest(r["receipt"]) for r in records]
        retained = StreamingMonitoring(backend.directory, total=True, paths=research_paths())
        restored = await retained.restore_latest()
        assert restored["network"]["inference_count"] == 0 and not restored["collection_live"]
        assert [digest(r["receipt"]) for r in restored["research"]["records"]] == before
        return owner.directory, snapshot, owner.store.runtime.verify_audit()

    try:
        directory, result, audit = asyncio.run_coroutine_threadsafe(run(), worker.loop).result(60)
    finally:
        worker.submit("close").result(40)
        worker.shutdown()
    assert not worker.thread.is_alive() and worker.loop.is_closed()
    archive = Archive(directory.parent)
    archived = archive.archive_inactive()
    assert archived["active"] == 0 and len(archived["archived"]) == 1
    assert archive.verify(directory.name)["audit_digest"] == audit
    evidence = {
        "scope": "ACTUAL_RF_LR_SYNTHETIC_FIXTURE_NOT_NATIVE",
        "elapsed_seconds": time.monotonic() - started,
        "controller_cpu_seconds": time.process_time() - cpu,
        "finalization": result["network"]["finalization"],
        "network": result["network"],
        "receipts": [r["receipt"] for r in result["research"]["records"]],
        "investigations": len(result["research"]["records"]),
        "audit_digest": audit,
        "archive_verified": True,
        "worker_stopped": True,
    }
    output = os.getenv("SOC_SLIMMING_INTEGRATION_EVIDENCE")
    if output:
        Path(output).write_text(json.dumps(evidence, indent=2))
