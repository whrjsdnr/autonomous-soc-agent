"""Opt-in bounded 20s per candidate, same ticks and simulated UNKNOWN worker."""

import asyncio
import json
import os
import time
from pathlib import Path

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import UnknownMockAdapter, packet
from tests.total_monitoring_support import dns_packet

from soc_agent.security_ai.operational.network_capture.calibrated_policy import CANDIDATES, policy
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.getenv("SOC_CALIBRATED_SOAK") != "1", reason="Explicit bounded candidate soak"
)
@pytest.mark.parametrize("name", CANDIDATES)
async def test_same_200_ticks_per_candidate_with_safe_failure(tmp_path, monkeypatch, name):
    monkeypatch.setattr(
        "soc_agent.security_ai.operational.network_capture.calibrated_policy.hardware",
        lambda: dict(affinity_cpus=4, available_memory_bytes=8 * 1024**3),
    )
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    worker = UnknownMockAdapter()
    samples = []

    async def source():
        for i in range(200):
            yield packet(owner, i * 2, flags=16)
            if i % 20 == 0:
                yield dns_packet(owner, i * 2 + 0.1)
                yield dns_packet(owner, i * 2 + 0.5, response=True)
            if i % 10 == 0:
                samples.append(
                    dict(
                        rss=owner.metrics.get("runtime_rss_bytes"),
                        queue=owner.metrics.get("queue_backlog", 0),
                        metadata=owner.aggregator.bytes,
                    )
                )
            await asyncio.sleep(0.1)

    cpu, start = time.process_time(), time.monotonic()
    await owner.start_fixture(source(), policy=policy(name), model_adapter=worker)
    await owner.task
    elapsed = time.monotonic() - start
    assert elapsed >= 20 and owner.state == "STOPPED"
    assert not owner.aborted and owner.metrics["queue_backlog"] == 0
    assert owner.metrics["inference_count"] == 0 and worker.calls == 1
    assert owner.metrics["retained_metadata_bytes"] == 0
    assert owner.snapshot()["dns"]["counts"]["MATCHED_RESPONSE"] == 10
    assert owner.metrics["inference_capacity_exclusions"] > 0
    record = dict(
        scope="FIXTURE_SAME_200_TICKS_NO_NATIVE_NO_REAL_MODEL",
        policy=name,
        elapsed_seconds=elapsed,
        cpu_seconds=time.process_time() - cpu,
        packets=owner.metrics["packets_collected"],
        flow_records=owner.flow_count,
        sampled_peak_rss=max(s["rss"] for s in samples if s["rss"] is not None),
        peak_queue=max(s["queue"] for s in samples),
        retained_metadata=0,
        model_calls=0,
        mock_unknown_calls=worker.calls,
        audit_head=owner.store.runtime.verify_audit(),
        samples=samples,
    )
    if os.getenv("SOC_CALIBRATED_SOAK_OUTPUT"):
        Path(os.environ["SOC_CALIBRATED_SOAK_OUTPUT"], name + ".json").write_text(
            json.dumps(record, indent=2)
        )
