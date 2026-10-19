"""Opt-in 60s processing soak, synthetic event time and simulated worker failure."""

import asyncio
import json
import os
import time
from pathlib import Path

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import UnknownMockAdapter, packet
from tests.total_monitoring_support import dns_packet

from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.getenv("SOC_ISOLATION_SOAK") != "1", reason="Explicit 60s fixture soak opt-in"
)
async def test_isolation_soak_has_bounded_retention_and_audited_failure(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    worker = UnknownMockAdapter()
    samples = []
    started = time.monotonic()

    async def source():
        yield packet(owner, 0, port=4000)
        yield packet(owner, 1, port=4000)
        yield packet(owner, 0.999989, port=4000)
        tick = 0
        while time.monotonic() - started < 60:
            event_time = tick * 2 + 2
            yield packet(owner, event_time, flags=16)
            if tick % 20 == 0:
                yield dns_packet(owner, event_time + 0.1)
                yield dns_packet(owner, event_time + 0.25, response=True)
            if tick % 10 == 0:
                samples.append(
                    dict(
                        elapsed=time.monotonic() - started,
                        rss_bytes=int(Path("/proc/self/statm").read_text().split()[1])
                        * os.sysconf("SC_PAGE_SIZE"),
                        cpu_seconds=time.process_time(),
                        queue=owner.metrics.get("queue_backlog", 0),
                        flow_records=owner.flow_count,
                        metadata_bytes=owner.aggregator.bytes,
                        quarantined=owner.aggregator.snapshot()["quarantined_flow_keys"],
                    )
                )
            tick += 1
            await asyncio.sleep(0.1)

    await owner.start_fixture(source(), model_adapter=worker)
    await owner.task
    elapsed = time.monotonic() - started
    final = owner.snapshot()
    assert elapsed >= 60 and owner.state == "STOPPED", owner.last_error
    assert final["network"]["quarantined_flow_count"] == 1
    assert worker.calls == 1  # Unknown outcome is never automatically retried.
    assert final["network"]["inference_count"] == 0
    assert not owner.aggregator.bytes
    assert final["network"]["queue_backlog"] == 0
    assert not list((owner.directory / "inputs").glob("input-*.json"))
    assert max(s["rss_bytes"] for s in samples) <= owner.policy.rss_bytes
    assert max(s["metadata_bytes"] for s in samples) <= owner.policy.metadata_bytes
    assert final["dns"]["counts"]["MATCHED_RESPONSE"] > 0
    result = dict(
        validation="EXPLICIT_SYNTHETIC_FIXTURE_NO_NATIVE_CAPTURE",
        elapsed_monotonic_seconds=elapsed,
        source_origin="FIXTURE",
        packets=owner.metrics["packets_collected"],
        flow_records=owner.flow_count,
        packet_processing_rate=owner.metrics["packets_collected"] / elapsed,
        flow_completion_rate=owner.flow_count / elapsed,
        model_inference_count=0,
        inference_latency="UNKNOWN_MOCK_WORKER_ONLY",
        mock_worker_unknown_calls=worker.calls,
        peak_sampled_rss_bytes=max(s["rss_bytes"] for s in samples),
        cpu_seconds=samples[-1]["cpu_seconds"] - samples[0]["cpu_seconds"],
        queue_peak=max(s["queue"] for s in samples),
        final_queue=0,
        retained_packet_metadata_bytes=owner.aggregator.bytes,
        quarantine=owner.aggregator.snapshot(),
        audit_head=owner.store.runtime.verify_audit(),
        dns=final["dns"]["counts"],
        samples=samples,
        native_capture=False,
        operational_gate="BLOCKED",
    )
    output = os.getenv("SOC_ISOLATION_SOAK_OUTPUT")
    if output:
        with Path(output).open("x") as f:
            json.dump(dict(result=result, result_digest=digest(result)), f, indent=2)
