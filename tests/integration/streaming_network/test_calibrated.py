"""Same workload per policy; real RF/LR are strictly Fixture, never Native approvals."""

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
from soc_agent.security_ai.operational.network_capture.stream_session import RateBudget
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_service import StreamingMonitoring
from soc_agent.security_ai.research.total_auth import TerminalAuthentication


@pytest.mark.asyncio
@pytest.mark.parametrize("name", CANDIDATES)
async def test_identical_candidate_load_actual_artifacts_parity_audit_recovery(tmp_path, name):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    p = policy(name)
    limiter = RateBudget(p.frames_per_second, p.burst_frames, 0)
    latencies = []
    original = owner.observe

    async def observed(*args):
        before = time.perf_counter()
        try:
            return await original(*args)
        finally:
            latencies.append(time.perf_counter() - before)

    owner.observe = observed

    async def source():
        values = [
            packet(owner, 0),
            packet(owner, 0.5, reverse=True, length=60, flags=16),
            packet(owner, 1, flags=1, length=80),
            dns_packet(owner, 2),
            dns_packet(owner, 2.25, response=True),
        ]
        values += [packet(owner, 3 + i / 100, port=3000, flags=16) for i in range(256)]
        values += [packet(owner, 33), dns_packet(owner, 33.25)]
        first = values[0].timestamp
        for value in values:
            now = (value.timestamp - first).total_seconds()
            limiter.consume(now)
            limiter.consume(now)  # Explicit synthetic raw clone pair.
            yield value

    cpu, start = time.process_time(), time.monotonic()
    await owner.start_fixture(source(), policy=p)
    await asyncio.wait_for(owner.task, 40)
    elapsed, cpu = time.monotonic() - start, time.process_time() - cpu
    result = owner.snapshot()
    assert owner.last_error is None and owner.metrics["finalization"] == "VERIFIED"
    assert owner.metrics["packets_collected"] == 263 and owner.metrics["inference_count"] == 4
    assert owner.metrics["inference_capacity_exclusions"] == 0
    assert owner.metrics["inference_queue"]["peak"] <= 8 and owner.metrics["queue_backlog"] == 0
    assert owner.metrics["gap_count"] == 0
    assert result["dns"]["counts"]["MATCHED_RESPONSE"] == 1
    assert result["dns"]["dns9_inference"] == "BLOCKED"
    models = []
    for row in result["research"]["records"]:
        receipt = row["receipt"]
        assert receipt["origin"] == "FIXTURE" and receipt["producer_version"] == "1.1.0"
        assert len(receipt["feature_values"]) == 14
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
        assert row["integrity_status_current"] == "FLOW_LOCAL_VERIFIED"
        models.append(
            dict(
                profile=receipt["profile"],
                values=receipt["feature_values"],
                score=receipt["score"],
                prediction=receipt["prediction"],
                artifact_digest=receipt["artifact_digest"],
                receipt_digest=digest(receipt),
                feature_digest=receipt["feature_digest"],
            )
        )
    audit = owner.store.runtime.verify_audit()
    restored = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    recovered = await restored.restore_latest()
    assert recovered["network"]["selected_rate_policy"] == name
    assert recovered["network"]["policy_approval"] == "RETAINED_NOT_CURRENT_AUTHORIZATION"
    assert recovered["network"]["inference_count"] == 0 and not recovered["collection_live"]
    assert [digest(r["receipt"]) for r in recovered["research"]["records"]] == [
        digest(r["receipt"]) for r in result["research"]["records"]
    ]
    output = os.getenv("SOC_CALIBRATED_COMPARISON")
    if output:
        from tests.total_rate_profile import summary

        record = dict(
            policy=p.model_dump(mode="json"),
            native=False,
            scope="ACTUAL_RF_LR_ON_IDENTICAL_263_PACKET_SYNTHETIC_FIXTURE",
            elapsed_seconds=elapsed,
            cpu_seconds=cpu,
            peak_metadata_bytes=owner.metrics["peak_metadata_bytes"],
            sampled_rss_bytes=owner.metrics["runtime_rss_bytes"],
            inference_queue=owner.metrics["inference_queue"],
            errors=0,
            packets=263,
            raw_simulated_frames=526,
            models=models,
            investigations=4,
            audit_head=audit,
            dns=result["dns"]["counts"],
            finalization=owner.metrics["finalization"],
            observe_latency=summary(latencies, cpu_seconds=cpu, elapsed_seconds=elapsed),
        )
        Path(output, name + ".json").write_text(json.dumps(record, indent=2))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "STREAM_RATE_BUDGET_EXCEEDED",
        "HELPER_CAPTURE_COUNTER_UNAVAILABLE",
        "HELPER_CAPTURE_DROPS_DETECTED",
        "STREAM_PACKET_SEQUENCE_MISMATCH",
        "HELPER_TRANSPORT_BACKPRESSURE",
        "HELPER_DISCONNECTED_OR_RECORD_LIMIT",
    ],
)
async def test_candidate_shared_failures_remain_fail_closed(tmp_path, failure):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())

    async def source():
        yield packet(owner, 0)
        yield dns_packet(owner, 1)
        raise ValueError(failure)

    await owner.start_fixture(
        source(), policy=policy("performance-v2"), model_adapter=UnknownMockAdapter()
    )
    await owner.task
    result = owner.snapshot()
    assert result["network"]["capture_integrity"] == "CAPTURE_INTEGRITY_FAILED"
    assert result["dns"]["diagnostic_status"] == "DNS_DIAGNOSTIC_BLOCKED"
    assert result["network"]["inference_count"] == 0
    assert result["network"]["recovery_state"] == "NO_AUTOMATIC_RETRY"
    assert result["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
    owner.store.runtime.verify_audit()


@pytest.mark.asyncio
async def test_candidate_scope_auth_is_separate_and_launcher_is_mocked(tmp_path):
    from tests.unit.streaming_network.test_auth import Process

    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    command = await owner.start(policy=policy("performance-v2"))
    calls = []

    async def launcher(*args, **kwargs):
        calls.append((args, kwargs))
        return Process(1)

    auth = TerminalAuthentication(launcher=launcher)
    try:
        with pytest.raises(ValueError, match="SCOPE_EXPLICIT_APPROVAL_REQUIRED"):
            await auth.start(owner, command["helper_sha256"])
        assert not calls
        await auth.start(
            owner,
            command["helper_sha256"],
            approved_policy="performance-v2",
            approved_bundle=command["bundle_digest"],
        )
        await auth.task
        args, kw = calls[0]
        assert "--approval-digest" in args and "calibrated_helper" in " ".join(args)
        assert "--no-new-privs" in args and "-S" not in args
        assert kw["stdin"] == asyncio.subprocess.DEVNULL
        assert not owner.snapshot()["collection_live"]
    finally:
        await owner.stop(abort=True)
        await auth.cancel()


@pytest.fixture(autouse=True)
def controlled_fixture_headroom(monkeypatch):
    # Policy behavior test only: not a Native resource-readiness assertion.
    monkeypatch.setattr(
        "soc_agent.security_ai.operational.network_capture.calibrated_policy.hardware",
        lambda: dict(affinity_cpus=4, available_memory_bytes=8 * 1024**3),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", ["dns", "sqlite"])
async def test_candidate_bounded_processing_delay_and_graceful_recovery(
    tmp_path, monkeypatch, delay
):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    worker = UnknownMockAdapter()

    async def source():
        if delay == "dns":
            original = owner.dns_diagnostics.observe

            def slow(*args):
                time.sleep(0.005)
                return original(*args)

            monkeypatch.setattr(owner.dns_diagnostics, "observe", slow)
        else:
            original = owner.store.commit

            def slow(*args, **kw):
                time.sleep(0.05)
                return original(*args, **kw)

            monkeypatch.setattr(owner.store, "commit", slow)
        for t in (0, 0.5, 1, 31):
            yield packet(owner, t)
        yield dns_packet(owner, 32)
        yield dns_packet(owner, 32.5, response=True)

    await owner.start_fixture(source(), policy=policy("performance-v2"), model_adapter=worker)
    await owner.task
    assert owner.state == "STOPPED" and not owner.aborted
    assert owner.metrics["packets_collected"] == 6
    assert owner.snapshot()["dns"]["counts"]["MATCHED_RESPONSE"] == 1
    assert worker.calls == 1 and owner.metrics["inference_count"] == 0
    assert owner.metrics["queue_backlog"] == 0
    owner.store.runtime.verify_audit()


@pytest.mark.asyncio
async def test_candidate_timestamp_quarantine_keeps_independent_dns(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())

    async def source():
        yield packet(owner, 1)
        yield packet(owner, 0.999989)
        yield dns_packet(owner, 2)
        yield dns_packet(owner, 2.5, response=True)

    await owner.start_fixture(
        source(), policy=policy("performance-v2"), model_adapter=UnknownMockAdapter()
    )
    await owner.task
    result = owner.snapshot()
    assert not owner.aborted and result["network"]["quarantined_flow_count"] == 1
    assert result["dns"]["counts"]["MATCHED_RESPONSE"] == 1
    assert owner.metrics["inference_count"] == 0
    assert result["network"]["retained_integrity_health"] == "DEGRADED"
