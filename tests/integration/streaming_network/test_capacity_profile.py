"""Opt-in measured offline profile, real RF/LR only in the explicitly named stage."""

import asyncio
import json
import os
import platform
import socket
import time
from pathlib import Path
from uuid import uuid4

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import packet
from tests.total_monitoring_support import total_source
from tests.total_rate_profile import measure, summary
from tests.unit.live_network.test_parity import request
from tests.unit.network_capture.test_packets import dns, frame
from tests.unit.network_capture.test_packets import packet as parsed

from soc_agent.security_ai.operational.network_capture.isolated_flow import IsolatedFlows
from soc_agent.security_ai.operational.network_capture.parsing import dns_message
from soc_agent.security_ai.research import service
from soc_agent.security_ai.research.live_input import produce
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_service import StreamingMonitoring

pytestmark = pytest.mark.skipif(
    not os.getenv("SOC_RATE_PROFILE"), reason="Explicit offline profile"
)


@pytest.mark.asyncio
async def test_processing_stages_actual_models_and_investigation(tmp_path, monkeypatch):
    paths = research_paths()
    monkeypatch.syspath_prepend(str((paths.producer_source or paths.ml) / "src"))
    stages = {}
    body = frame()
    value = parsed(body)
    stages["packet_parsing_including_dns"] = measure(lambda: parsed(body), 1000)
    stages["dns_extraction_only"] = measure(lambda: dns_message(dns(), retain_name=False), 1000)
    stages["metadata_serialization"] = measure(value.model_dump_json, 1000)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    payload = value.model_dump_json().encode()
    try:

        def transfer():
            left.sendall(payload)
            assert right.recv(8192) == payload

        stages["unix_seqpacket_send_receive_no_contention"] = measure(transfer, 1000)
    finally:
        left.close()
        right.close()
    # Build input before timing aggregation, preserve the original feature engine.
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    from types import SimpleNamespace

    fixture = SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))
    packets = [packet(fixture, i / 100, flags=16) for i in range(1000)]
    flows = IsolatedFlows()
    cursor = iter(packets)
    stages["streaming_aggregation"] = measure(lambda: flows.add(next(cursor), uuid4()), 1000)
    q = request(native=False)
    produce(q)  # Separate warm-up/import from steady-state Producer timing.
    stages["network14_producer_warm"] = measure(lambda: produce(q), 100)
    inference, investigation, commits = [], [], []
    original = service.investigate

    async def investigate(*args, **kwargs):
        before = time.perf_counter()
        try:
            return await original(*args, **kwargs)
        finally:
            investigation.append(time.perf_counter() - before)

    monkeypatch.setattr(service, "investigate", investigate)

    async def source():
        infer, commit = owner.demo.adapter.infer, owner.store.commit

        async def measured_infer(*args):
            before = time.perf_counter()
            try:
                return await infer(*args)
            finally:
                inference.append(time.perf_counter() - before)

        def measured_commit(*args, **kwargs):
            before = time.perf_counter()
            try:
                return commit(*args, **kwargs)
            finally:
                commits.append(time.perf_counter() - before)

        monkeypatch.setattr(owner.demo.adapter, "infer", measured_infer)
        monkeypatch.setattr(owner.store, "commit", measured_commit)
        async for p in total_source(owner):
            yield p

    cpu, before = time.process_time(), time.monotonic()
    await owner.start_fixture(source())
    await owner.task
    elapsed, cpu = time.monotonic() - before, time.process_time() - cpu
    result = owner.snapshot()
    assert result["network"]["inference_count"] == 4, owner.last_error
    assert result["dns"]["counts"]["MATCHED_RESPONSE"] == 1
    for name, samples in [
        ("sqlite_flow_commit", commits),
        ("isolated_model_worker_startup_producer_predict", inference),
        ("read_only_investigation", investigation),
    ]:
        stages[name] = summary(samples, cpu_seconds=cpu, elapsed_seconds=elapsed)
        stages[name]["accounting_scope"] = "shared_controller_total_run_not_stage_CPU"
        stages[name]["operations_per_second"] = (
            None  # Concurrent run denominator is not stage throughput.
        )
    receipts = [r["receipt"] for r in result["research"]["records"]]
    assert {r["profile"] for r in receipts} == {"quality", "edge"}
    record = dict(
        scope="SYNTHETIC_METADATA_ACTUAL_RF_LR_NO_NATIVE_CAPTURE",
        environment=dict(
            python=platform.python_version(), kernel=platform.release(), machine=platform.machine()
        ),
        stages=stages,
        end_to_end_seconds=elapsed,
        end_to_end_packets=7,
        actual_model_calls=4,
        investigations=len(investigation),
        models=[
            dict(
                profile=r["profile"],
                artifact=r["artifact_digest"],
                predict_latency_ms=r["inference_latency_ms"],
                worker_peak_rss_bytes=r["worker_peak_rss_bytes"],
                worker_cpu_seconds=r["worker_cpu_seconds"],
                receipt_digest=digest(r),
                feature_digest=r["feature_digest"],
                feature_contract_digest=r["feature_contract_digest"],
                source_origin=r["origin"],
            )
            for r in receipts
        ],
        audit_head=owner.store.runtime.verify_audit(),
        dns9_inference="BLOCKED",
    )
    out = os.getenv("SOC_RATE_PROFILE")
    if out:
        Path(out).write_text(
            json.dumps(dict(result=record, result_digest=digest(record)), indent=2)
        )


@pytest.mark.asyncio
async def test_identical_congestion_fixture_comparison(tmp_path):
    from tests.streaming_network_support import UnknownMockAdapter
    from tests.total_monitoring_support import dns_packet

    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())

    class HeldWorker(UnknownMockAdapter):
        def __init__(self):
            super().__init__()
            self.release = asyncio.Event()

        async def infer(self, request):
            await self.release.wait()
            return await super().infer(request)

    worker = HeldWorker()

    async def source():
        # Capture/task keeps making progress while the model invocation is held.
        for port in range(1000, 1012):
            for t in (0, 0.5, 31):
                yield packet(owner, t, port=port)
        yield dns_packet(owner, 32)
        yield dns_packet(owner, 32.5, response=True)
        worker.release.set()

    cpu, start = time.process_time(), time.monotonic()
    await owner.start_fixture(source(), model_adapter=worker)
    # Bound the experiment in both implementations, even on an unexpected bug.
    try:
        await asyncio.wait_for(asyncio.shield(owner.task), 3)
    except TimeoutError:
        await owner.stop(abort=True)
    result = owner.snapshot()
    record = dict(
        scope="IDENTICAL_SYNTHETIC_CONGESTION_FIXTURE_NOT_NATIVE_THROUGHPUT",
        input_packets=38,
        state=owner.state,
        abort_reason=owner.last_error,
        packets_processed=owner.metrics["packets_collected"],
        inference_excluded=owner.metrics.get("inference_capacity_exclusions"),
        dns_matched=result["dns"]["counts"].get("MATCHED_RESPONSE", 0),
        elapsed_monotonic_seconds=time.monotonic() - start,
        controller_cpu_seconds=time.process_time() - cpu,
        rss_bytes=int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE"),
        actual_model_inferences=owner.metrics["inference_count"],
        audit_head=owner.store.runtime.verify_audit(),
    )
    out = os.environ["SOC_RATE_PROFILE"] + ".congestion.json"
    Path(out).write_text(json.dumps(record, indent=2))
