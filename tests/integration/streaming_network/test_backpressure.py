"""Model congestion is not packet loss. Shared capture failure remains fail-closed."""

import asyncio
import json

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import UnknownMockAdapter, packet
from tests.total_monitoring_support import dns_packet

from soc_agent.realtime.queue import QueueFull
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


class SlowUnknown(UnknownMockAdapter):
    def __init__(self):
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def infer(self, request):
        self.entered.set()
        await self.release.wait()
        return await super().infer(request)


def events(owner, kind):
    with owner.store.runtime.database.transaction(write=False) as c:
        return [
            json.loads(r[0])["details"]
            for r in c.execute(
                "SELECT payload FROM monitor_audit WHERE json_extract(payload,'$.kind')=?",
                (kind,),
            )
        ]


@pytest.mark.asyncio
async def test_slow_model_full_queue_preserves_collection_dns_and_audited_exclusion(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    model = SlowUnknown()

    async def source():
        for port in range(1000, 1012):
            for t in (0, 0.5, 31):
                yield packet(owner, t, port=port)
        yield dns_packet(owner, 32)
        yield dns_packet(owner, 32.25, response=True)
        assert owner.metrics["inference_capacity_exclusions"] >= 4
        assert owner.store.queue.counts()["PENDING"] <= 8
        assert owner.inference_pressure.peak == 8
        assert not owner.aborted
        model.release.set()

    await owner.start_fixture(source(), model_adapter=model)
    await asyncio.wait_for(owner.task, 30)
    result = owner.snapshot()
    assert owner.state == "STOPPED" and not owner.aborted
    assert result["dns"]["counts"]["MATCHED_RESPONSE"] == 1
    excluded = events(owner, "STREAM_FLOW_INFERENCE_EXCLUDED")
    assert len(excluded) == owner.metrics["inference_capacity_exclusions"]
    assert all(
        e["capture_gap"] is False and e["disposition"] == "NOT_INFERRED_NO_RETRY" for e in excluded
    )
    assert len({e["flow_id"] for e in excluded}) == len(excluded)
    assert owner.metrics["packets_collected"] == 38
    assert owner.metrics["gap_count"] == 0
    assert owner.metrics["inference_count"] == 0  # Simulated UNKNOWN, no fabricated receipts.
    assert model.calls == 1 and owner.metrics["queue_backlog"] == 0
    assert not list((owner.directory / "inputs").glob("input-*.json"))
    assert result["network"]["retained_integrity_health"] == "DEGRADED"
    restored = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    recovered = await restored.restore_latest()
    assert recovered["network"]["inference_capacity_exclusions"] == len(excluded)
    assert recovered["network"]["current_raw_frame_rate"] is None
    assert recovered["network"]["worker_health"] == "STOPPED"
    assert recovered["network"]["inference_count"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "STREAM_RATE_BUDGET_EXCEEDED",
        "HELPER_TRANSPORT_BACKPRESSURE",
        "HELPER_CAPTURE_COUNTER_UNAVAILABLE",
        "HELPER_CAPTURE_DROPS_DETECTED",
    ],
)
async def test_shared_window_failure_blocks_both_domains_and_audits_scope(tmp_path, failure):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())

    async def source():
        yield packet(owner, 0)
        yield dns_packet(owner, 1)
        raise ValueError(failure)

    await owner.start_fixture(source(), model_adapter=UnknownMockAdapter())
    await owner.task
    result = owner.snapshot()
    assert owner.aborted and result["network"]["integrity_scope"] == "CAPTURE_WIDE"
    assert result["dns"]["diagnostic_status"] == "DNS_DIAGNOSTIC_BLOCKED"
    assert result["network"]["dns_diagnostic_status"] == "DNS_DIAGNOSTIC_BLOCKED"
    (window,) = events(owner, "TOTAL_CAPTURE_WINDOW_QUARANTINED")
    assert window["accepted_packet_prefix"] == 2
    assert len(window["affected_flow_keys"]) == 2
    assert window["unobserved_packet_count"] is None
    assert window["model_eligibility"] == "BLOCKED" and not window["automatic_retry"]
    assert owner.metrics["inference_count"] == 0 and owner.metrics["gap_count"] == 1
    if failure.startswith("STREAM_RATE"):
        assert owner.metrics["rate_budget_state"] == "EXCEEDED_CAPTURE_WINDOW_BLOCKED"
    owner.store.runtime.verify_audit()


@pytest.mark.asyncio
async def test_non_capacity_storage_failure_still_aborts_capture(tmp_path, monkeypatch):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())

    async def source():
        def failed(*args, **kwargs):
            raise QueueFull("STREAM_FLOW_RETENTION_LIMIT")

        monkeypatch.setattr(owner.store, "commit", failed)
        for t in (0, 0.5, 31):
            yield packet(owner, t)

    await owner.start_fixture(source(), model_adapter=UnknownMockAdapter())
    await owner.task
    assert owner.aborted and owner.last_error == "STREAM_FLOW_RETENTION_LIMIT"
    assert not events(owner, "STREAM_FLOW_INFERENCE_EXCLUDED")


@pytest.mark.asyncio
@pytest.mark.parametrize("fps", [64, 128, 256, 512])
async def test_virtual_load_preserves_all_packet_dispositions(tmp_path, fps):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())

    async def source():
        for i in range(fps * 2):
            yield packet(owner, i / fps, flags=16)

    await owner.start_fixture(source(), model_adapter=UnknownMockAdapter())
    await owner.task
    assert not owner.aborted
    assert owner.metrics["packets_collected"] == fps * 2
    # Packet-limit flows are diagnostic, never forced into RF/LR to inflate success.
    assert owner.metrics["inference_count"] == 0
    dispositions = events(owner, "STREAM_FLOW_EXCLUDED")
    assert sum(e["packets"] for e in dispositions) == fps * 2
    assert owner.metrics["retained_metadata_bytes"] == 0
    assert owner.metrics["queue_backlog"] == 0
