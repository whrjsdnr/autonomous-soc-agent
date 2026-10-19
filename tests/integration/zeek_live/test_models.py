"""Real streamed Zeek output + unchanged RF/LR. Offline origin; never Native success."""

import asyncio
import json
import os
import resource
import time
from pathlib import Path

import pytest
from tests.research_adapter_support import research_paths
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.export import export
from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.offline import OfflineZeek
from soc_agent.security_ai.research.models import digest, parse_receipt


@pytest.mark.asyncio
async def test_streamed_zeek_actual_rf_lr_read_only_recovery(tmp_path):
    available = int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0]) * 1024
    psi = Path("/proc/pressure/memory").read_text()
    if available < 2 * 1024**3 or float(psi.split("avg10=")[1].split()[0]) >= 1:
        pytest.skip("ACTUAL_MODEL_HEADROOM_REQUIRED")
    try:
        OfflineZeek().environment()
    except (OSError, ValueError):
        pytest.skip("OFFICIAL_IMAGE_NOT_INSTALLED")
    pcap = tmp_path / "input.pcap"
    sha = golden(pcap)
    c = LiveZeekCollector(tmp_path, paths=research_paths())
    start, cpu = time.monotonic(), time.process_time()
    try:
        await c.prepare(pcap=pcap, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 80)
        snap = c.snapshot()
        assert c.state == "STOPPED", c.last_error
        assert c.producer.new_inferences == 2
        assert c.stream.closed and c.stream.packet_count == 4
        assert c.queue_peak <= 32 and c.queue_depth == 0
        assert c.producer.pending == 0 and c.producer.queue_peak == 2
        assert c.producer.state == "VERIFIED_RECEIPT_WINDOWS_RESEARCH_ONLY"
        records = snap["research"]["records"]
        assert len(records) == 2
        for record in records:
            r = parse_receipt(record["receipt"])
            assert r.origin == "ZEEK_OFFLINE_PCAP"
            assert r.pcap_sha256 == sha and r.producer_version == "1.1.0"
            assert r.network14_parity == "VERIFIED_FOR_BOUND_WINDOW"
            assert r.status == "RESEARCH_ONLY" and r.write_policy == "WRITE_DENIED"
            assert record["investigation"]["status"] == "ASSESSED_READ_ONLY"
            assert record["investigation"]["action_policy"] == "WRITE_DENIED"
        assert c.process_runner.cleanup_verified
        assert c.producer.demo.adapter.process is None
        export(c, tmp_path / "report.json", "json")
        export(c, tmp_path / "report.md", "markdown")
        receipts = [digest(r["receipt"]) for r in records]
        key = records[0]["key"]
        request = c.producer.request(c.producer.proof["flows"][0], "quality")
        cached = await c.producer.demo.dispatch(request, key)
        assert cached["status"] == "CACHED_NO_NEW_INFERENCE"
        audit = c.store.runtime.verify_audit()
        await c.stop()
        restored = LiveZeekCollector(tmp_path, paths=research_paths())
        result = await restored.recover()
        assert [digest(r["receipt"]) for r in result["research"]["records"]] == receipts
        assert result["collector"]["metrics"]["inference_count"] == 0
        assert not result["collection_live"] and restored.task is None
        assert result["network"]["recovery_state"] == "RESTORED_NO_CAPTURE_OR_INFERENCE_RESTART"
        with pytest.raises(ValueError, match="NO_NEW_INFERENCE"):
            restored.producer.authorize(request)
        if os.getenv("SOC_ZEEK_LIVE_MODEL_EVIDENCE"):
            Path(os.environ["SOC_ZEEK_LIVE_MODEL_EVIDENCE"]).write_text(
                json.dumps(
                    dict(
                        scope="ACTUAL_ZEEK_REALTIME_PROTOCOL_FROM_OFFLINE_PCAP_NOT_NATIVE",
                        # Persist the tested plan/exit proof with receipts: pytest may
                        # remove its temporary session on a later verification run.
                        stream_plan=c.plan.model_dump(mode="json"),
                        stream_exit=json.loads((c.directory / "exit.json").read_text()),
                        session_id=snap["session_id"],
                        pcap_sha256=sha,
                        input_origin=snap["input_origin"],
                        records=records,
                        collector_metrics=snap["collector"]["metrics"],
                        packet_count=c.stream.packet_count,
                        flow_count=len(c.stream.finalized),
                        queue_peak=c.queue_peak,
                        queue_final=c.queue_depth,
                        inference_queue_peak=c.producer.queue_peak,
                        inference_queue_final=c.producer.pending,
                        finalization=snap["network"]["finalization"],
                        audit_digest=audit,
                        recovered_audit_digest=restored.store.runtime.verify_audit(),
                        restored_new_inferences=0,
                        elapsed_seconds=time.monotonic() - start,
                        cpu_seconds=time.process_time() - cpu,
                        process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                        * 1024,
                        memavailable_before_bytes=available,
                        psi_before=psi,
                        native_capture=False,
                        cleanup_verified=c.process_runner.cleanup_verified,
                    ),
                    indent=2,
                )
            )
        await restored.stop()
    finally:
        await c.stop()
