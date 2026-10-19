"""Actual RF/LR and DNS fixture on shared capture-free Total runtime, with recovery."""

import asyncio
import json
import os
import time
from pathlib import Path

import pytest
from tests.research_adapter_support import research_paths
from tests.total_monitoring_support import total_source

from soc_agent.security_ai.operational.network_capture.calibrated_policy import policy
from soc_agent.security_ai.research.models import SPECS, digest
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
async def test_total_network_dns_projection_actual_models_audit_restore(tmp_path):
    available = int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0]) * 1024
    if available < 2 * 1024**3:
        pytest.skip("REAL_MODEL_HEADROOM_REQUIRED")
    owner = StreamingMonitoring(tmp_path / "total", paths=research_paths(), total=True)
    started, cpu = time.monotonic(), time.process_time()
    try:
        await owner.start_fixture(total_source(owner), policy=policy("balanced-v2"))
        await asyncio.wait_for(owner.task, 40)
        snap = owner.snapshot()
        net = snap["network"]
        records = snap["research"]["records"]
        assert net["packets_collected"] == net["dns_diagnostic_inputs"] == 7
        assert net["analysis_network_metadata_reused"] == 4
        assert net["analysis_network_metadata_copies"] == 3
        assert net["analysis_dns_snapshot_skipped"] == 3
        assert net["analysis_dns_snapshot_rebuilt"] == 4
        assert net["finalization"] == "VERIFIED" and net["queue_backlog"] == 0
        assert snap["runtime_audit_integrity"] == "VERIFIED"
        assert snap["dns"]["counts"]["MATCHED_RESPONSE"] == 1
        assert snap["dns"]["dns9_inference"] == "BLOCKED"
        assert len(records) == 4 and net["inference_count"] == 4
        for record in records:
            r = record["receipt"]
            assert r["artifact_digest"] == SPECS[r["profile"]]["sha256"]
            assert r["origin"] == "FIXTURE" and r["producer_version"] == "1.1.0"
            assert len(r["feature_values"]) == 14
            assert record["investigation"]["status"] == "ASSESSED_READ_ONLY"
        before = [digest(r["receipt"]) for r in records]
        audit = owner.store.runtime.verify_audit()
        with owner.store.runtime.database.transaction(write=False) as connection:
            audit_prefix = [
                tuple(row)
                for row in connection.execute(
                    "SELECT sequence,payload,digest FROM monitor_audit ORDER BY sequence"
                )
            ]

        elapsed = time.monotonic() - started
        fields = (
            "profile artifact_digest feature_digest feature_values origin producer_version "
            "prediction score invocation_id inferred_at inference_latency_ms worker_peak_rss_bytes"
        ).split()
        evidence = {
            "scope": "ACTUAL_RF_LR_DNS_SYNTHETIC_FIXTURE_NOT_NATIVE",
            "elapsed_seconds": elapsed,
            "cpu_seconds": time.process_time() - cpu,
            "network": net,
            "dns": snap["dns"],
            "receipts": [
                {k: r["receipt"][k] for k in fields if k in r["receipt"]} for r in records
            ],
            "receipt_digests": before,
            "read_only_investigations": 4,
            "audit_digest": audit,
        }
        await owner.stop()
        recovered = StreamingMonitoring(tmp_path / "total", paths=research_paths(), total=True)
        restore = await recovered.restore_latest()
        assert restore["network"]["inference_count"] == 0 and not restore["collection_live"]
        assert [digest(r["receipt"]) for r in restore["research"]["records"]] == before
        recovered_audit = recovered.store.runtime.verify_audit()
        with recovered.store.runtime.database.transaction(write=False) as connection:
            restored_rows = [
                tuple(row)
                for row in connection.execute(
                    "SELECT sequence,payload,digest FROM monitor_audit ORDER BY sequence"
                )
            ]
        assert restored_rows[: len(audit_prefix)] == audit_prefix
        evidence["recovered_audit_digest"] = recovered_audit
        evidence["original_audit_prefix_unchanged"] = True
        await recovered.stop()
        evidence.update(
            recovery="VERIFIED_NO_NEW_INFERENCE", operational_gate=restore["operational_gate"]
        )
        if os.getenv("SOC_FILTER_MODEL_EVIDENCE"):
            Path(os.environ["SOC_FILTER_MODEL_EVIDENCE"]).write_text(json.dumps(evidence, indent=2))
    finally:
        await owner.stop()
    assert owner.demo.adapter.process is None or owner.demo.adapter.process.returncode is not None
