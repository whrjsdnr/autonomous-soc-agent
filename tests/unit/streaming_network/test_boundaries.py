"""No native collection; fail-closed state, retention and authority tests."""

import asyncio
from types import SimpleNamespace

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import UnknownMockAdapter, idle_source, packet

from soc_agent.gui.charts import MetricHistory
from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["origin", "memory", "flow_capacity", "disk"])
async def test_fixture_fault_stops_without_capture_or_model_receipt(tmp_path, fault):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    adapter = UnknownMockAdapter()

    async def source():
        if fault == "origin":
            yield packet(owner, 0).model_copy(update={"interface_id": "f" * 64})
        elif fault == "memory":
            for i in range(30):
                yield packet(owner, i / 100)
        elif fault == "flow_capacity":
            yield packet(owner, 0, port=2001)
            yield packet(owner, 1, port=2002)
        else:
            owner.policy = owner.policy.model_copy(update={"disk_bytes": 1})
            yield packet(owner, 0)

    policy = StreamPolicy(metadata_bytes=8192, active_flows=1)
    await owner.start_fixture(source(), policy=policy, model_adapter=adapter)
    await asyncio.wait_for(owner.task, 10)
    assert owner.state == "ERROR"
    assert owner.metrics["finalization"] == "BLOCKED"
    assert owner.metrics["gap_count"] == 1
    assert owner.aggregator.bytes == 0
    assert adapter.calls == 0
    assert owner.snapshot()["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
    assert not owner.snapshot()["collection_live"]


@pytest.mark.asyncio
async def test_audit_corruption_is_not_displayed_verified_or_live(tmp_path):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    await owner.start_fixture(idle_source(owner), model_adapter=UnknownMockAdapter())
    await owner.task
    with owner.store.runtime.database.transaction() as c:
        c.execute("UPDATE monitor_audit SET digest=? WHERE sequence=1", ("f" * 64,))
    snapshot = owner.snapshot()
    assert snapshot["state"] == "UNKNOWN"
    assert snapshot["research"]["audit_integrity"] == "INVALID"
    assert snapshot["last_error"] == "STREAM_AUDIT_OR_RECEIPT_INVALID"
    assert not snapshot["collection_live"]


@pytest.mark.asyncio
async def test_mock_worker_cancel_drains_unknown_without_retry(tmp_path):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    waiting = asyncio.Event()

    class Hanging(UnknownMockAdapter):
        async def infer(self, request):
            self.calls += 1
            waiting.set()
            await asyncio.Event().wait()

    adapter = Hanging()

    async def source():
        async for p in idle_source(owner):
            yield p
        await waiting.wait()

    await owner.start_fixture(
        source(), policy=StreamPolicy(graceful_seconds=1), model_adapter=adapter
    )
    await asyncio.wait_for(owner.task, 8)
    assert owner.state == "STOPPED"
    assert owner.metrics["finalization"] == "PARTIAL"
    assert adapter.calls == 1
    assert owner.store.queue.counts() == {"DONE": 1}
    assert not list((owner.directory / "inputs").glob("*"))
    assert not owner.snapshot()["research"]["worker_running"]


def test_unattested_source_cannot_authorize_native_model(tmp_path):
    owner = StreamingMonitoring(tmp_path)
    owner.capture = SimpleNamespace(ready=True, counter_totals=[1, 0], counter_sequence=2)
    with pytest.raises(ValueError, match="AUTHENTICATED_COUNTER"):
        owner.authorize(SimpleNamespace())


def test_gui_chart_only_uses_actual_metrics_and_preserves_unknown():
    history = MetricHistory()
    history.observe({"network": {}}, now=1)
    first = history.samples[-1]
    assert first.rss_mib is None and first.drops is None and first.inference_rate is None
    history.observe(
        {
            "queue_backlog": 2,
            "network": {
                "runtime_rss_bytes": 2 * 1024**2,
                "runtime_cpu_seconds": 0.5,
                "capture_drops": 0,
                "gap_count": 1,
                "flows_per_minute": 3,
                "inferences_per_minute": 2,
            },
        },
        now=2,
    )
    last = history.samples[-1]
    assert (last.queue, last.rss_mib, last.cpu_seconds, last.flow_rate, last.drops, last.gaps) == (
        2,
        2,
        0.5,
        3,
        0,
        1,
    )


def test_root_gui_rejected_before_window_creation(monkeypatch, capsys):
    from soc_agent.gui.__main__ import main

    monkeypatch.setattr("sys.argv", ["soc-gui"])
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert main() == 1
    assert "UNPRIVILEGED_USER" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_crash_loses_active_memory_but_restore_marks_gap_not_active(tmp_path):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    observed = asyncio.Event()

    async def source():
        yield packet(owner, 0)
        observed.set()
        await asyncio.Event().wait()

    await owner.start_fixture(source(), model_adapter=UnknownMockAdapter())
    await observed.wait()
    assert owner.metrics["active_flows"] == 1
    owner.task.cancel()  # Simulated parent task loss; no real helper exists.
    await asyncio.gather(owner.task, return_exceptions=True)
    await owner.consumer
    restored = StreamingMonitoring(tmp_path, paths=research_paths())
    value = await restored.restore_latest()
    assert value["network"]["retained_previous_active_flows"] == 1
    assert value["network"]["active_flows"] == 0
    assert value["network"]["retained_metadata_bytes"] == 0
    assert value["network"]["restart_gap"]
    assert value["network"]["inference_count"] == 0
    assert not value["research"]["records"]
    assert not value["collection_live"]


def test_delayed_gui_poll_cannot_override_newer_stop():
    from soc_agent.gui.live_view import LiveView

    view = LiveView.__new__(LiveView)
    view.observation_started_ns = 0
    assert view.accept_observation(
        {"observation_started_ns": 100, "state": "AUTHENTICATION_REQUIRED"}
    )
    assert view.accept_observation({"observation_started_ns": 200, "state": "STOPPED"})
    assert not view.accept_observation(
        {"observation_started_ns": 100, "state": "AUTHENTICATION_REQUIRED"}
    )
    assert not view.accept_observation({"observation_started_ns": "300"})
    assert view.observation_started_ns == 200
