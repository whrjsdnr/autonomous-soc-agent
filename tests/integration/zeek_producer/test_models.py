import asyncio
import json
import os
from pathlib import Path

import pytest
from tests.research_adapter_support import research_paths
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.export import export
from soc_agent.security_ai.collectors.offline import OfflineZeek
from soc_agent.security_ai.collectors.zeek import ZeekCollector
from soc_agent.security_ai.research.models import AdvisoryContext, digest, parse_receipt
from soc_agent.security_ai.research.zeek_input import validate_result


@pytest.mark.asyncio
async def test_actual_zeek_input_quality_edge_investigation_and_recovery(tmp_path):
    available = int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0]) * 1024
    if available < 2 * 1024**3:
        pytest.skip("ACTUAL_MODEL_HEADROOM_REQUIRED")
    try:
        OfflineZeek().environment()
    except (ValueError, OSError):
        pytest.skip("OFFICIAL_ZEEK_IMAGE_NOT_INSTALLED")
    pcap = tmp_path / "input.pcap"
    sha = golden(pcap)
    c = ZeekCollector(tmp_path, packet_mode=True, paths=research_paths())
    try:
        await c.prepare(pcap=pcap, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 80)
        snap = c.snapshot()
        assert c.state == "STOPPED", (c.last_error, snap.get("collector", {}).get("producer"))
        producer = snap["collector"]["producer"]
        assert producer["state"] == "VERIFIED_RECEIPT_WINDOWS_RESEARCH_ONLY", producer
        assert producer["eligible"] == 1 and producer["rejected"] == 1
        assert producer["new_inferences"] == 2
        records = snap["research"]["records"]
        assert len(records) == 2
        for record in records:
            r = parse_receipt(record["receipt"])
            assert r.origin == "ZEEK_OFFLINE_PCAP" and r.status == "RESEARCH_ONLY"
            assert r.pcap_sha256 == sha and r.producer_origin == "OFFLINE_PCAP"
            assert tuple(r.feature_values) == (
                1.0,
                2.0,
                1.0,
                120.0,
                60.0,
                40.0,
                80.0,
                60.0,
                16.329931259155273,
                1.0,
                1.0,
                0.0,
                0.5,
                0.5,
            )
            request = c.producer.request(c.producer.proof["flows"][0], r.profile).model_copy(
                update={"invocation_id": r.invocation_id}
            )
            validate_result(request, r)
            i = record["investigation"]
            assert i["status"] == "ASSESSED_READ_ONLY" and i["action_policy"] == "WRITE_DENIED"
            context = AdvisoryContext.model_validate(i["context"])
            assert (
                context.mode == "OFFLINE_RESEARCH_DEMO"
                and context.result.origin == "ZEEK_OFFLINE_PCAP"
            )
        before = [digest(r["receipt"]) for r in records]
        key = records[0]["key"]
        request = c.producer.request(c.producer.proof["flows"][0], "quality")
        cached = await c.producer.demo.dispatch(request, key)
        assert cached["status"] == "CACHED_NO_NEW_INFERENCE"
        assert len(c.producer.demo.snapshot()["records"]) == 2
        export(c, tmp_path / "research.json", "json")
        export(c, tmp_path / "research.md", "markdown")
        assert len(json.loads((tmp_path / "research.json").read_text())["inference_receipts"]) == 2
        audit = c.store.runtime.verify_audit()
        await c.stop()
        fresh = ZeekCollector(tmp_path, packet_mode=True, paths=research_paths())
        restored = await fresh.recover()
        assert [digest(r["receipt"]) for r in restored["research"]["records"]] == before
        assert restored["collector"]["metrics"]["inference_count"] == 0
        assert fresh.producer.state == "RESTORED_NO_NEW_INFERENCE"
        assert not restored["collection_live"] and restored["runtime_audit_integrity"] == "VERIFIED"
        with pytest.raises(ValueError, match="NO_NEW_INFERENCE"):
            fresh.producer.authorize(request)
        if os.getenv("SOC_ZEEK_MODEL_EVIDENCE"):
            Path(os.environ["SOC_ZEEK_MODEL_EVIDENCE"]).write_text(
                json.dumps(
                    dict(
                        scope="ACTUAL_ZEEK_OFFLINE_PCAP_RF_LR_NOT_NATIVE",
                        pcap_sha256=sha,
                        session_id=snap["session_id"],
                        producer=producer,
                        records=records,
                        audit_digest=audit,
                        recovered_audit_digest=fresh.store.runtime.verify_audit(),
                        recovered_new_inferences=0,
                        operational_gate=snap["operational_gate"],
                        collector_metrics=snap["collector"]["metrics"],
                        process_cleanup=c.runner.container is None,
                        model_worker_stopped=c.producer.demo.adapter.process is None,
                    ),
                    indent=2,
                )
            )
        await fresh.stop()
    finally:
        await c.stop()
