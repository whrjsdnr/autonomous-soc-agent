"""Continuous sealed-window contracts; no Root, Kernel, traffic or API calls.

Successful model cases use FIXTURE evidence and actual pinned RF/LR. Native-shaped
negative cases exercise action gates, never claim actual Native verification.
"""

import json
from uuid import NAMESPACE_URL, uuid5

import pytest
from tests.research_adapter_support import research_paths
from tests.unit.ebpf_tc.test_batch2_window import complete

from soc_agent.continuous.capture import CaptureSeal, CaptureWindows, sealed_jobs
from soc_agent.continuous.tcx_producer import ContinuousEvent
from soc_agent.gui.analysis_service import AnalysisService, project_result
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.tcx_input import candidates

NS = "net:[4026532232]"
SESSION = uuid5(NAMESPACE_URL, "7")


def transcript():
    _, _, windows, clocks, _, _ = complete()
    body = dict(
        contract="soc-continuous-seal:v1",
        namespace=NS,
        session=str(SESSION),
        generation=7,
        program_sha256="a" * 64,
        policy_sha256="b" * 64,
        release_manifest="f" * 64,
        cpu_windows=windows,
        clock_samples=clocks,
        callbacks=3,
        transport_dropped=0,
        cleanup="VERIFIED",
        drain_result=0,
    )
    seal = CaptureSeal.model_validate(body | dict(seal_sha256=digest(body)))
    events = []
    for index, stamp in enumerate((1000, 2000, 31_000_001_000), 1):
        events.append(
            ContinuousEvent(
                collector="EBPF_TCX",
                session_id=SESSION,
                program_sha256="a" * 64,
                plan_digest="c" * 64,
                generation=7,
                ifindex=1,
                cpu=0,
                cpu_sequence=index,
                net_namespace=NS,
                hook="INGRESS",
                delivery_sequence=index,
                timestamp_ns=stamp,
                clock="KERNEL_MONOTONIC_NS",
                source="192.0.2.1",
                destination="192.0.2.2",
                source_port=111 if index < 3 else 222,
                destination_port=443,
                protocol="udp",
                frame_length=54,
                ip_length=40,
                tcp_flags=0,
            )
        )
    return seal, events


def reseal(body):
    body.pop("seal_sha256", None)
    return CaptureSeal.model_validate(body | dict(seal_sha256=digest(body)))


def test_seal_reuses_phase_d_and_independent_window_id():
    seal, events = transcript()
    jobs, capture = sealed_jobs(seal, events, origin="FIXTURE")
    assert capture["status"] == "VERIFIED"
    assert capture["source"] == "FIXTURE_NOT_NATIVE"
    assert len(jobs) == 1
    receipts = candidates(jobs[0])[2]
    assert [r["input_state"] for r in receipts] == ["ELIGIBLE", "INCOMPLETE"]
    assert receipts[0]["flow_completion"] == "COMPLETE"
    assert receipts[1]["flow_completion"] == "INCOMPLETE"
    assert jobs == sealed_jobs(seal, events, origin="FIXTURE")[0]
    assert jobs[0].result["tcx"]["data_plane"]["continuous_window"]["id"] == seal.identity


@pytest.mark.parametrize(
    "fault",
    [
        "counter",
        "ring",
        "clock",
        "epoch",
        "drop",
        "partial",
        "disabled",
        "baseline",
        "drain",
        "cleanup",
        "schema",
        "cpu_gap",
        "seal_digest",
        "namespace",
        "cpu_set",
    ],
)
def test_bad_attestation_never_eligible(fault):
    seal, events = transcript()
    value = seal.model_dump(mode="json")
    if fault == "counter":
        value["cpu_windows"][2]["counters"]["emitted"] = 2
    elif fault == "ring":
        value["cpu_windows"][2]["counters"].update(observed=4, ring_reservation_failures=1)
    elif fault == "clock":
        value["clock_samples"][-1]["wall_ns"] += 10**9
    elif fault == "epoch":
        value["clock_samples"][-1]["generation"] = 8
    elif fault == "drop":
        value["transport_dropped"] = 1
    elif fault == "partial":
        events.pop()
    elif fault == "disabled":
        value["cpu_windows"][2]["counters"].update(observed=4, disabled=1)
    elif fault == "baseline":
        value["cpu_windows"][0]["counters"].update(observed=1, emitted=1)
    elif fault == "drain":
        value["drain_result"] = -1
    elif fault == "cleanup":
        value["cleanup"] = "UNVERIFIED"
    elif fault == "schema":
        value["cpu_windows"][2]["counters"]["unknown"] = 0
    elif fault == "cpu_gap":
        events[-1] = events[-1].model_copy(update=dict(cpu_sequence=4))
    elif fault == "namespace":
        value["namespace"] = "net:[1]"
    elif fault == "cpu_set":
        value["cpu_windows"][2]["cpu"] = 1
    else:
        value["seal_sha256"] = "0" * 64
    try:
        edited = CaptureSeal.model_validate(value) if fault == "seal_digest" else reseal(value)
        jobs, capture = sealed_jobs(edited, events, origin="FIXTURE")
    except ValueError:
        return
    assert capture["status"] != "VERIFIED"
    assert not any(r["eligible"] for j in jobs for r in candidates(j)[2])


@pytest.mark.asyncio
async def test_sealed_fixture_real_rf_lr_incident_audit_and_gui_projection(tmp_path):
    j = sealed_jobs(*transcript(), origin="FIXTURE")[0][0]
    result = await OfflineWorkflow(tmp_path / "analysis", paths=research_paths()).run(j)
    assert len(result.inference) == 2
    assert result.eligibility == "ELIGIBLE"
    assert all(r.receipt["origin"] == "FIXTURE" for r in result.inference)
    assert result.external_provider_calls == 0
    assert verify_result(tmp_path / "analysis") == result
    projected = project_result(result)
    assert projected["input_origins"] == ["FIXTURE"]
    assert projected["audit"] == "VERIFIED" and projected["inference_count"] == 2
    assert all(r.evidence_references for r in result.inference)


@pytest.mark.asyncio
async def test_native_shaped_window_requires_exact_existing_action(tmp_path, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Unapproved inference")

    monkeypatch.setattr(ResearchAdapter, "infer", forbidden)
    j = sealed_jobs(*transcript())[0][0]
    result = await OfflineWorkflow(tmp_path / "analysis", paths=research_paths()).run(j)
    assert result.eligibility == "ELIGIBLE" and not result.inference
    assert "TCX_MODEL_ACTION_APPROVAL_REQUIRED" in result.reasons
    assert verify_result(tmp_path / "analysis") == result


def test_retained_seal_mutation_cannot_pass_existing_vector_validator():
    j = sealed_jobs(*transcript(), origin="FIXTURE")[0][0]
    raw = j.model_dump(mode="json")
    raw["result"]["tcx"]["data_plane"]["continuous_window"]["id"] = "0" * 64
    with pytest.raises(ValueError, match="SEAL_BINDING"):
        candidates(type(j).model_validate(raw))


def raw_event(event):
    from soc_agent.security_ai.ebpf.ring import ABI

    a, b = event.source, event.destination
    wire = ABI.pack(
        event.generation,
        event.ns,
        event.cpu_sequence,
        1,
        event.cpu,
        event.frame_length,
        event.ip_length,
        event.source_port,
        event.destination_port,
        a.version,
        17,
        0,
        1,
        a.packed.ljust(16, b"\0"),
        b.packed.ljust(16, b"\0"),
    )
    return dict(
        kind="native_tcx",
        id=str(uuid5(SESSION, str(event.sequence))),
        sequence=event.sequence,
        window_sequence=event.sequence,
        wire_hex=wire.hex(),
        session=str(event.session_id),
        program=event.program_sha256,
    )


def test_transcript_recovery_and_replay_rejected():
    seal, events = transcript()
    rows = [raw_event(e) for e in events]
    final = dict(
        kind="native_seal",
        id=str(uuid5(SESSION, "seal")),
        sequence=4,
        seal=seal.model_dump(mode="json"),
    )
    first, restored = CaptureWindows(NS, "b" * 64), CaptureWindows(NS, "b" * 64)
    for raw in rows:
        assert first.accept(raw)[0] == []
        restored.accept(json.loads(json.dumps(raw)))
    a, b = first.accept(final), restored.accept(final)
    assert a == b and a[1]["status"] == "VERIFIED"
    with pytest.raises(ValueError, match="REPLAY"):
        restored.accept(final)
    with pytest.raises(ValueError, match="REPLAY"):
        restored.accept(rows[0])
    other = CaptureWindows("net:[1]", "b" * 64)
    with pytest.raises(ValueError, match="SCOPE"):
        other.accept(final)


def test_new_epoch_discards_partial_not_promoted():
    _, events = transcript()
    w = CaptureWindows(NS, "b" * 64)
    w.accept(raw_event(events[0]))
    new = events[0].model_copy(update=dict(generation=8, session_id=uuid5(NAMESPACE_URL, "8")))
    w.accept(raw_event(new))
    assert w.abandoned == 1 and w.last_capture["status"] == "INCOMPLETE"
    assert len(w.events) == 1 and w.generation == 8


@pytest.mark.asyncio
async def test_actual_retained_cli_entry_fixture_models(tmp_path):
    j = sealed_jobs(*transcript(), origin="FIXTURE")[0][0]
    path = tmp_path / "window.json"
    path.write_text(j.model_dump_json())
    service = AnalysisService(tmp_path / "service", research_paths().ml)
    with pytest.raises(ValueError, match="APPROVAL_ENTRYPOINT"):
        await service.start(path)
    await service.start_retained_tcx(path)
    await service.monitor
    assert service.snapshot()["state"] == "COMPLETED"
    assert service.snapshot()["result"]["inference_count"] == 2
    assert service.snapshot()["cleanup"] == "VERIFIED"
    assert verify_result(service.output).evidence[0].origin == "FIXTURE"
    with pytest.raises(FileExistsError):
        await service.start_retained_tcx(path)  # immutable attempt: no automatic rerun
    await service.close()


@pytest.mark.asyncio
async def test_runtime_queue_real_fixture_models_and_durable_result(tmp_path):
    import asyncio

    from tests.unit.continuous.test_runtime import make

    from soc_agent.continuous.service import ContinuousRuntime

    path, store = make(tmp_path, ml_root=research_paths().ml)
    j = sealed_jobs(*transcript(), origin="FIXTURE")[0][0]
    store.enqueue(j)
    runtime = ContinuousRuntime(path)
    task = asyncio.create_task(runtime.consume())
    try:
        for _ in range(400):
            if runtime.last_results or runtime.circuit:
                break
            await asyncio.sleep(0.05)
        assert runtime.metrics["predictions"] == 2 and runtime.metrics["incidents"] == 1
        assert runtime.last_results[0]["origins"] == ["FIXTURE"]
        assert store.queue.counts() == {"DONE": 1}
        assert verify_result(runtime.analysis.output).inference
    finally:
        runtime.stop.set()
        await asyncio.wait_for(task, 3)
        await runtime.analysis.close()


@pytest.mark.asyncio
async def test_native_window_waits_for_model_permission_without_starting_worker(tmp_path):
    import asyncio

    from tests.unit.continuous.test_runtime import make

    from soc_agent.continuous.service import ContinuousRuntime

    path, store = make(tmp_path)
    j = sealed_jobs(*transcript())[0][0]
    store.enqueue(j)
    runtime = ContinuousRuntime(path)
    task = asyncio.create_task(runtime.consume())
    for _ in range(100):
        if runtime.worker_state == "WAITING_EXACT_MODEL_ACTION_APPROVAL":
            break
        await asyncio.sleep(0.01)
    assert runtime.worker_state == "WAITING_EXACT_MODEL_ACTION_APPROVAL"
    assert runtime.analysis.process is None
    assert runtime.metrics["predictions"] == 0
    runtime.stop.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert list((path / "inputs").glob("*.json"))  # evidence survives denied admission/Stop
    await runtime.analysis.close()


@pytest.mark.asyncio
async def test_actual_unix_seal_transport_and_epoch_rotation(tmp_path, monkeypatch):
    """Actual Unix framing; Root credentials and installed authority are explicitly MOCK."""
    import asyncio
    import os
    import socket
    import struct

    from tests.unit.continuous.test_runtime import config

    from soc_agent.continuous import tcx_producer as producer

    seal, events = transcript()
    files = {"continuous.bpf.o": "a" * 64}
    seal = reseal(seal.model_dump(mode="json") | dict(release_manifest=digest(files)))
    cfg = config(tmp_path).model_copy(update=dict(input_sha256="b" * 64))
    base = socket.socket
    endpoint = str(tmp_path / "seal.sock")
    server = base(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(endpoint)
    server.listen(1)
    server.setblocking(False)

    class PeerSocket(base):
        def connect(self, address):
            return super().connect(endpoint)

        def getsockopt(self, level, opt, *args):
            if opt == socket.SO_PEERCRED:
                # Mock only Root credentials; retain a real PID/start identity.
                return struct.pack("3i", os.getpid(), 0, 0)
            return super().getsockopt(level, opt, *args)

    monkeypatch.setattr(
        producer, "installed", lambda: dict(uid=os.getuid(), namespace=NS, files=files)
    )
    monkeypatch.setattr(producer.socket, "socket", PeerSocket)
    source = producer.TCXProducer(cfg)
    loop = asyncio.get_running_loop()

    async def send():
        peer, _ = await loop.sock_accept(server)
        try:
            for generation, sequence, frames, proof in (
                (7, 1, [raw_event(e)["wire_hex"] for e in events], seal.model_dump(mode="json")),
                (8, 2, [], None),
            ):
                packet = dict(
                    contract="soc-continuous-tcx:v1",
                    namespace=NS,
                    ifindex=1,
                    program_sha256="a" * 64,
                    generation=generation,
                    sequence=sequence,
                    frames=frames,
                    seal=proof,
                    clock=[1000, 2000, 1001],
                    state=dict(state="RUNNING", counters={}),
                )
                await loop.sock_sendall(peer, json.dumps(packet).encode())
            await loop.sock_sendall(
                peer,
                json.dumps(
                    dict(
                        contract="soc-continuous-tcx-stop:v1",
                        generation=8,
                        namespace=NS,
                        policy_sha256=cfg.input_sha256,
                        cleanup="VERIFIED",
                    )
                ).encode(),
            )
        finally:
            peer.close()

    task = asyncio.create_task(send())
    try:
        records = [record async for record in source.events()]
        assert [r["kind"] for r in records] == ["native_tcx"] * 3 + ["native_seal"]
        assert [r["sequence"] for r in records] == [1, 2, 3, 4]
        restored = CaptureWindows(NS, "b" * 64)
        for record in records:
            jobs, _ = restored.accept(record)
        assert candidates(jobs[0])[2][0]["eligible"]
        assert source.remote_cleanup == "VERIFIED" and source.socket is None
        assert source.snapshot["generation"] == 8
        assert source.snapshot["counters"] == {}
        await source.request_stop()  # already-bound ACK remains valid after receiver closes FD
    finally:
        await task
        server.close()
        await source.close()


@pytest.mark.asyncio
async def test_durable_native_handoff_crash_before_seal_application(tmp_path):
    from tests.unit.continuous.test_runtime import config

    from soc_agent.continuous.service import ContinuousRuntime
    from soc_agent.continuous.store import Store

    cfg = config(tmp_path).model_copy(update=dict(source="NATIVE_SERVICE", input_sha256="b" * 64))
    path = tmp_path / "native-shape-storage"
    store = Store.create(path, cfg)
    runtime = ContinuousRuntime(path, source=object())  # no Root socket or authority calls
    seal, events = transcript()
    rows = [raw_event(e) for e in events]
    for raw in rows:
        await runtime.observe(raw)
    assert runtime.metrics["packets"] == runtime.metrics["native_events"] == len(events)
    final = dict(
        kind="native_seal",
        id=str(uuid5(SESSION, "seal")),
        sequence=4,
        seal=seal.model_dump(mode="json"),
    )
    store.retain_auxiliary("native-window:" + final["id"], final)  # crash boundary
    recovered = CaptureWindows(NS, "b" * 64)
    for raw in store.auxiliary():
        jobs, _ = recovered.accept(raw)
        for job in jobs:
            store.enqueue(job)
    assert store.queue.counts() == {"PENDING": 1}
    second = CaptureWindows(NS, "b" * 64)
    for raw in store.auxiliary():
        jobs, _ = second.accept(raw)
        for job in jobs:
            assert not store.enqueue(job)
    assert store.queue.counts() == {"PENDING": 1}
    assert runtime.metrics["predictions"] == 0
    await runtime.analysis.close()


@pytest.mark.asyncio
async def test_native_flow_counters_recompute_eligibility_without_model_authority(tmp_path):
    from tests.integration.test_tcx_ai_workflow import job
    from tests.unit.continuous.test_runtime import make

    from soc_agent.continuous.service import ContinuousRuntime

    directory, store = make(tmp_path)
    runtime = ContinuousRuntime(directory)
    # Synthetic Native-shaped evidence includes one eligible and one rejected Flow.
    retained = job(native=True)
    try:
        await runtime.handoff(retained)
        assert runtime.metrics["flows"] == 2
        assert runtime.metrics["eligible"] == runtime.metrics["incomplete"] == 1
        assert runtime.metrics["predictions"] == runtime.metrics["incidents"] == 0
        assert runtime.analysis.process is None and store.queue.counts() == {"PENDING": 1}
    finally:
        await runtime.analysis.close()


def test_root_serializer_and_finish_cleanup_are_real_functions(monkeypatch):
    from soc_agent.continuous.native import service

    seal, _ = transcript()
    policy = dict(namespace=NS, files={"continuous.bpf.o": "a" * 64})
    serialized = service.seal_record(
        policy, "b" * 64, 7, list(seal.cpu_windows), list(seal.clock_samples), 3, 0
    )
    checked = CaptureSeal.model_validate(serialized)
    checked.check()
    assert checked.release_manifest == digest(policy["files"])
    calls = []
    provider = service.Provider.__new__(service.Provider)
    provider.generation, provider.initial, provider.samples = 7, ["initial"], ["clock-start"]
    provider.boundary = lambda *args: calls.append("detach-drain-snapshot") or ["final"]
    provider.close = lambda: calls.append("close-owned-maps")
    monkeypatch.setattr(service, "clock_samples", lambda *args: ["clock-end"])
    assert provider.finish() == (["initial", "final"], ["clock-start", "clock-end"])
    assert calls == ["detach-drain-snapshot", "close-owned-maps"]

    def broken(*args):
        raise ValueError("FIRST_DRAIN_ERROR")

    provider.boundary = broken
    with pytest.raises(ValueError, match="FIRST_DRAIN_ERROR"):
        provider.finish()
    assert calls[-1] == "close-owned-maps"


def test_receiver_restart_same_epoch_reconciles_durable_prefix():
    seal, events = transcript()
    w = CaptureWindows(NS, "b" * 64)
    w.accept(raw_event(events[0]))
    second = raw_event(events[1]) | dict(sequence=1, window_sequence=1)
    third = raw_event(events[2]) | dict(sequence=2, window_sequence=2)
    w.accept(second)
    w.accept(third)
    jobs, capture = w.accept(dict(kind="native_seal", seal=seal.model_dump(mode="json")))
    assert capture["status"] == "VERIFIED"  # all actual CPU attempts remain represented
    assert candidates(jobs[0])[2][0]["eligible"]


def test_rate_state_is_separate_from_fresh_capture_baseline():
    from soc_agent.continuous.native.service import Provider

    class CounterLib:
        def continuous_cpus(self, handle):
            return 2

        def continuous_finish(self, handle, values, size):
            # All seven capture counters stay zero; minute state remains near quota.
            values[0], values[1] = 100, 110
            values[9], values[10] = 55, 4096
            values[18], values[19] = 55, 12
            return 0

    provider = Provider.__new__(Provider)
    provider.handle, provider.lib = 1, CounterLib()
    rows = provider.boundary("continuous_finish", "POST_DETACH")
    assert provider.rates == [55, 4096, 55, 12]
    assert all(not any(row["counters"].values()) for row in rows)


def test_detach_failure_cannot_be_reported_as_verified_cleanup():
    import errno

    from soc_agent.continuous.native.service import Provider

    class FailedDetach:
        def continuous_cpus(self, handle):
            return 1

        def continuous_finish(self, *args):
            return -errno.EUCLEAN

    provider = Provider.__new__(Provider)
    provider.lib, provider.handle = FailedDetach(), 1
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        provider.boundary("continuous_finish", "POST_DETACH")


def test_primary_error_keeps_cleanup_uncertainty_in_cause_chain():
    from soc_agent.continuous.native.service import cleanup_failed

    first = ValueError("FIRST_COUNTER_READ_FAILURE")
    first.__cause__ = ValueError("CONTINUOUS_TCX_CLEANUP_UNVERIFIED")
    assert cleanup_failed(first)
    assert str(first) == "FIRST_COUNTER_READ_FAILURE"
    assert not cleanup_failed(ValueError("FIRST_COUNTER_READ_FAILURE"))
