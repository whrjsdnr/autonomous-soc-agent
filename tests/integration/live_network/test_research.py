"""Actual reviewed model binaries on persisted AF_PACKET-shaped FIXTURE metadata. No capture."""

import asyncio
from datetime import timedelta
from uuid import uuid4

import pytest
from tests.unit.live_network.test_parity import wire

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig, FlowSummary
from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.live_input import LiveRequest
from soc_agent.security_ai.research.live_service import LiveResearch, bound_request
from soc_agent.security_ai.research.models import digest
from soc_agent.state.evidence import utc_now


def persisted(root):
    session = uuid4()
    initialize(root, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3))
    configure(root, CaptureConfig(interface="lo", origin="EXPLICIT_PACKET_FIXTURE"))
    monitor = NetworkMonitor(root, RuntimeStore(root), generation=str(session))
    base = utc_now() - timedelta(seconds=32)
    for i in range(3):
        packet = parse_packet(
            wire(reverse=i == 1, length=40 + 20 * i, flags=[2, 16, 1][i]),
            interface_id=monitor.identity,
            timestamp=base + timedelta(seconds=i * 0.5),
            direction="OUTBOUND",
            native=False,
        )
        assert monitor.pipeline.packet(packet, str(session), i + 1)
    while monitor.pipeline.step() != "IDLE":
        pass
    monitor.pipeline.flush(utc_now())
    assert monitor.pipeline.step() == "STORED"
    event, flow, _ = monitor.pipeline.last_committed
    assert isinstance(flow, FlowSummary)
    return monitor, session, event, flow


def key(request):
    return digest(
        {
            "session": str(request.capture_session),
            "flow": request.flow_id,
            "profile": request.profile,
        }
    )


@pytest.mark.asyncio
async def test_actual_two_models_fixture_advisory_checkpoint_duplicate_and_restart(tmp_path):
    monitor, session, event, flow = persisted(tmp_path / "runtime")
    demo = LiveResearch(tmp_path / "demo")
    await demo.start()
    requests = []
    for profile in ("quality", "edge"):
        request = bound_request(monitor, session, event, flow, profile)
        requests.append(request)
        result = await demo.dispatch(request, key(request))
        assert result["status"] == "COMPLETE", result
        receipt = result["record"]["receipt"]
        assert receipt["origin"] == "FIXTURE" and receipt["status"] == "RESEARCH_ONLY"
        assert (
            receipt["operational_inference"] == "BLOCKED"
            and receipt["capture_quality"] == "UNKNOWN"
        )
        inv = result["record"]["investigation"]
        assert inv["context"]["mode"] == "FIXTURE_RESEARCH_ADVISORY"
        assert inv["checkpoint_restored"] and inv["provider_calls"] == 0
        assert not inv["assessment"]["incident_state"]["observations"]
    before = demo.snapshot()
    assert before["model_metrics"]["quality"]["successful"] == 1
    assert before["model_metrics"]["edge"]["successful"] == 1
    await demo.stop()
    restored = LiveResearch(tmp_path / "demo")
    assert restored.snapshot()["records"] == before["records"]
    await restored.start()
    assert (await restored.dispatch(requests[0], key(requests[0])))[
        "status"
    ] == "CACHED_NO_NEW_INFERENCE"
    assert len(restored.snapshot()["records"]) == 2
    bad = requests[0].model_dump(mode="json")
    bad["packets"][0]["ip_length"] += 1
    bad["packets"][0]["frame_length"] += 1
    with pytest.raises(ValueError, match="CACHED_SOURCE"):
        await restored.dispatch(LiveRequest.model_validate(bad), key(requests[0]))
    assert monitor.pipeline.queue.counts() == {"DONE": 4}
    assert monitor.store.verify_audit()
    await restored.stop()


@pytest.mark.asyncio
async def test_actual_worker_timeout_is_unknown_and_never_retried(tmp_path):
    monitor, session, event, flow = persisted(tmp_path / "runtime")
    request = bound_request(monitor, session, event, flow, "quality")
    demo = LiveResearch(tmp_path / "demo", timeout=0.1)
    await demo.start()
    outcome = await demo.dispatch(request, key(request))
    assert outcome["status"] == "UNKNOWN" and demo.adapter.process is None
    assert (await demo.dispatch(request, key(request)))["status"] == "CACHED_NO_NEW_INFERENCE"
    assert demo.snapshot()["model_metrics"]["quality"]["successful"] == 0
    await demo.stop()


@pytest.mark.asyncio
async def test_worker_crash_and_contract_tamper_no_promotion(tmp_path, monkeypatch):
    monitor, session, event, flow = persisted(tmp_path / "runtime")
    request = bound_request(monitor, session, event, flow, "edge")
    adapter = ResearchAdapter(tmp_path / "adapter", live_metadata=True)

    class Crashed:
        returncode = 9

        async def wait(self):
            return 9

    async def crashed(*a, **k):
        return Crashed()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", crashed)
    outcome = await adapter.infer(request)
    assert outcome["status"] == "UNKNOWN" and adapter.process is None


def test_missing_source_and_recovery_gap_rejected(tmp_path):
    monitor, session, event, flow = persisted(tmp_path / "runtime")
    with pytest.raises(ValueError, match="SESSION"):
        bound_request(monitor, uuid4(), event, flow, "quality")
    with pytest.raises(ValueError, match="GAP"):
        bound_request(
            monitor,
            session,
            event,
            flow.model_copy(update={"close_reason": "RESTART_GAP"}),
            "quality",
        )
    with monitor.pipeline.sources.database.transaction() as c:
        c.execute("DELETE FROM operational_sources")
    with pytest.raises((ValueError, KeyError)):
        bound_request(monitor, session, event, flow, "quality")


def test_audit_corruption_is_not_repaired(tmp_path):
    monitor, session, event, flow = persisted(tmp_path / "runtime")
    assert bound_request(monitor, session, event, flow, "quality")
    with monitor.store.database.transaction() as c:
        c.execute("UPDATE monitor_audit SET digest=? WHERE sequence=1", ("0" * 64,))
    with pytest.raises(ValueError):
        monitor.store.verify_audit()
