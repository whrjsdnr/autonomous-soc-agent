"""Ordinary replay and explicit fault simulation; never Native attestation."""

import asyncio
import hashlib
from uuid import uuid4

import pytest
from tests.unit.live_network.test_parity import observation, wire

from soc_agent.continuous.cli import main, status
from soc_agent.continuous.models import ContinuousConfig, require_source_authority
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.source import ReplaySource
from soc_agent.continuous.store import Store
from soc_agent.security_ai.packet_window import validate_window
from soc_agent.security_ai.workflow_models import CollectorFailureJob, PacketWindowJob


def config(tmp_path, **updates):
    source = tmp_path / "source.jsonl"
    source.write_bytes(b"\n")
    return ContinuousConfig(
        source="JSONL_REPLAY",
        input_file=source,
        input_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        heartbeat_seconds=0.1,
        **updates,
    )


def make(tmp_path, **updates):
    path = tmp_path / "runtime"
    store = Store.create(path, config(tmp_path, **updates))
    return path, store


def window():
    packets = tuple(
        observation(
            wire(reverse=i == 1, flags=(2, 16, 1)[i]), 1_000_000_000 + i * 500_000_000, False
        )
        for i in range(3)
    )
    return PacketWindowJob(
        kind="packet_window",
        origin="FIXTURE",
        session=uuid4(),
        source_sha256="a" * 64,
        clock_epoch="fixture",
        quality="ELIGIBLE",
        close_reason="IDLE_TIMEOUT",
        packets=packets,
        identities=tuple(uuid4() for _ in packets),
        witness_ns=32_000_000_000,
    )


@pytest.mark.parametrize("quality", ["INCOMPLETE", "UNKNOWN", "INVALID"])
def test_quality_never_promoted(quality):
    assert validate_window(window().model_copy(update={"quality": quality})) == quality


def test_event_time_witness_and_identity():
    value = window()
    assert validate_window(value) == "ELIGIBLE"
    assert validate_window(value.model_copy(update={"witness_ns": 31_999_999_999})) == "INCOMPLETE"
    assert validate_window(value.model_copy(update={"close_reason": "SHUTDOWN"})) == "INCOMPLETE"
    assert validate_window(value.model_copy(update={"identities": (uuid4(),)})) == "INVALID"


def test_native_service_requires_separate_unactivated_authority(tmp_path, monkeypatch):
    from soc_agent.continuous.native import policy

    # The test must not depend on whether this workstation has an approved installation.
    monkeypatch.setattr(policy, "POLICY", tmp_path / "not-installed.json")
    cfg = config(tmp_path).model_copy(update={"source": "NATIVE_SERVICE"})
    with pytest.raises(ValueError, match="NOT_ACTIVATED"):
        require_source_authority(cfg)


def test_store_replay_and_tamper_fail_closed(tmp_path):
    _, store = make(tmp_path)
    assert not store.seen("event1", {"original": 1})
    assert store.seen("event1", {"original": 1})
    with pytest.raises(ValueError, match="IDENTITY_REUSE"):
        store.seen("event1", {"original": 2})
    store.event("TEST_EVIDENCE", {"original": 1})
    with store.database.transaction() as c:
        c.execute("UPDATE continuous_details SET payload='{}'")
    with pytest.raises(ValueError, match="AUDIT_DETAIL_CHANGED"):
        store.state()


@pytest.mark.asyncio
async def test_source_partial_record_and_sha_rejected(tmp_path):
    cfg = config(tmp_path)
    cfg.input_file.write_bytes(b"{}")
    cfg = cfg.model_copy(update={"input_sha256": hashlib.sha256(b"{}").hexdigest()})
    with pytest.raises(ValueError, match="PARTIAL_SOURCE"):
        _ = [item async for item in ReplaySource(cfg).events()]
    cfg = cfg.model_copy(update={"input_sha256": "a" * 64})
    with pytest.raises(ValueError, match="INPUT_SHA"):
        _ = [item async for item in ReplaySource(cfg).events()]


@pytest.mark.asyncio
async def test_backpressure_accounts_exact_drop(tmp_path):
    path, _ = make(tmp_path, queue_capacity=1)
    runtime = ContinuousRuntime(path)
    await runtime.handoff(CollectorFailureJob(kind="collector_error", code="TEST_A"))
    await runtime.handoff(CollectorFailureJob(kind="collector_error", code="TEST_B"))
    assert runtime.metrics["queue_dropped"] == 1
    assert runtime.store.queue.counts()["PENDING"] == 1
    await runtime.analysis.close()


@pytest.mark.asyncio
async def test_clock_gap_invalidates_pending_flow(tmp_path):
    path, _ = make(tmp_path)
    runtime = ContinuousRuntime(path)
    for index, packet in enumerate(window().packets[:2], 1):
        await runtime.observe(
            dict(
                sequence=index,
                id=str(uuid4()),
                kind="packet",
                packet=packet.model_dump(mode="json"),
            )
        )
    packet = window().packets[0]
    with pytest.raises(ValueError, match="CLOCK_REVERSED"):
        await runtime.observe(
            dict(sequence=3, id=str(uuid4()), kind="packet", packet=packet.model_dump(mode="json"))
        )
    assert runtime.metrics["eligible"] == 0
    assert runtime.metrics["incomplete"] == 1
    await runtime.analysis.close()


class FaultSource:
    """Explicit collector fault, not a Native collector."""

    def __init__(self):
        self.calls = 0
        self.closed = False

    async def events(self):
        self.calls += 1
        yield dict(sequence=1, id=str(uuid4()), kind="excluded", affects_integrity=False)
        raise ValueError("SIMULATED_COLLECTOR_FAILURE")

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_collector_bounded_recovery_and_stop(tmp_path):
    path, store = make(tmp_path)
    source = FaultSource()
    runtime = ContinuousRuntime(path, source=source)
    task = asyncio.create_task(runtime.run())
    for _ in range(100):
        await asyncio.sleep(0.02)
        if runtime.collector_state == "CIRCUIT_OPEN":
            break
    assert source.calls == 2
    assert runtime.metrics["collector_restarts"] == 1
    assert "SIMULATED_COLLECTOR_FAILURE" in runtime.last_error
    assert not task.done()  # AI/service lifecycle outlives failed collector.
    store.control(stop=True)
    await asyncio.wait_for(task, 5)
    assert store.state()["cleanup"] == "VERIFIED"
    assert source.closed


class FailedAnalysis:
    """Explicit process boundary failure; no fabricated AI output."""

    async def start(self, path):
        self.monitor = asyncio.create_task(asyncio.sleep(0))

    def snapshot(self):
        return {"state": "ERROR", "result": None}

    async def close(self):
        return True


@pytest.mark.asyncio
async def test_worker_circuit_does_not_stop_collector_or_replay_poison(tmp_path):
    path, _ = make(tmp_path, worker_circuit_failures=1)
    runtime = ContinuousRuntime(path, analysis=FailedAnalysis())
    await runtime.handoff(CollectorFailureJob(kind="collector_error", code="TEST"))
    consumer = asyncio.create_task(runtime.consume())
    for _ in range(100):
        await asyncio.sleep(0.01)
        if runtime.circuit:
            break
    assert runtime.store.queue.counts()["POISON"] == 1
    assert runtime.metrics["model_errors"] == 1
    assert not runtime.stop.is_set()
    runtime.stop.set()
    await asyncio.wait_for(consumer, 2)


def test_cli_code_integrity_and_stale_heartbeat(tmp_path, capsys):
    cfg = config(tmp_path)
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(cfg.model_dump_json())
    path = tmp_path / "runtime"
    assert main(["init", str(path), "--config", str(cfg_path)]) == 0
    (path / "code-identity").write_text("0" * 64)
    assert main(["start", str(path)]) == 2
    assert "INTEGRITY_CHANGED" in capsys.readouterr().out
    store = Store(path)
    store.update({"state": "RUNNING", "heartbeat_unix": 0})
    assert status(path)["state"] == "UNKNOWN_STALE_HEARTBEAT"
    assert not store.state().get("collection_live", False)


@pytest.mark.asyncio
async def test_5000_events_no_diagnostic_event_cap(tmp_path):
    path, _ = make(tmp_path)
    runtime = ContinuousRuntime(path)
    for seq in range(1, 5001):
        await runtime.observe(
            dict(
                sequence=seq,
                id=str(uuid4()),
                kind="excluded",
                event_ns=seq * 60_000_000_000,
                affects_integrity=False,
            )
        )
    assert runtime.metrics["received"] == 5000
    assert runtime.metrics["source_gaps"] == 0
    assert runtime.snapshot()["collection_live"] is False
    await runtime.analysis.close()


@pytest.mark.asyncio
async def test_packet_window_real_models_and_verified_audit(tmp_path):
    """Synthetic packet bytes / REAL_MODEL / SCRIPTED / OFFLINE, zero API."""
    from pathlib import Path

    from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
    from soc_agent.security_ai.research.environment import Paths

    ml = Path("/home/geonug/kdt-linux/ML")
    python = ml.parent / "autonomous-soc-agent/.security-ai-demo/inference/bin/python"
    if not python.exists():
        pytest.skip("Explicit existing research model environment unavailable")
    paths = Paths(ml, python, Path(__file__).resolve().parents[3] / "src")
    result = await OfflineWorkflow(tmp_path / "out", paths=paths).run(window())
    assert result.eligibility == "ELIGIBLE"
    assert len(result.inference) == 2
    assert {p.model_id for p in result.inference} == {
        "linux-network14-research-v1-quality_rf",
        "linux-network14-research-v1-edge_lr",
    }
    assert result.external_provider_calls == 0
    assert verify_result(tmp_path / "out").incident_id == result.incident_id


@pytest.mark.asyncio
async def test_retransmitted_event_deduplicated_across_transport_sequence(tmp_path):
    path, _ = make(tmp_path)
    runtime = ContinuousRuntime(path)
    raw = dict(sequence=1, id=str(uuid4()), kind="excluded", affects_integrity=False)
    await runtime.observe(raw)
    await runtime.observe(raw | dict(sequence=2))
    assert runtime.metrics["duplicates"] == 1
    assert runtime.metrics["excluded"] == 1
    with pytest.raises(ValueError, match="IDENTITY_REUSE"):
        await runtime.observe(raw | dict(sequence=3, affects_integrity=True))
    await runtime.analysis.close()


@pytest.mark.asyncio
async def test_multi_hour_event_time_windows_remain_bounded(tmp_path):
    """Synthetic five event-time hours, not a five-hour wall-clock/Native soak."""
    from tests.streaming_network_support import packet
    from tests.unit.streaming_network.test_flows import owner

    path, _ = make(tmp_path, queue_capacity=1, max_windows=1000)
    runtime = ContinuousRuntime(path)
    for sequence in range(1, 601):
        p = packet(owner(), sequence * 31)
        await runtime.observe(
            dict(
                sequence=sequence, id=str(uuid4()), kind="packet", packet=p.model_dump(mode="json")
            )
        )
    assert runtime.metrics["eligible"] == 599
    assert runtime.metrics["queue_dropped"] == 598
    assert runtime.aggregator.bytes < 8 * 1024**2
    assert len(runtime.aggregator.stats) == 1
    assert not runtime.snapshot()["collection_live"]
    await runtime.analysis.close()
