"""Monotonic streaming observations remain separate from retained UTC/event time."""

import asyncio
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import UnknownMockAdapter, packet

import soc_agent.linux_runtime.store as runtime_store
import soc_agent.security_ai.research.stream_service as stream_service
from soc_agent.gui.live_view import LiveView
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
async def test_monotonic_uptime_advances_when_store_utc_moves_back(tmp_path, monkeypatch):
    owner = StreamingMonitoring(tmp_path, paths=research_paths())
    entered, release = asyncio.Event(), asyncio.Event()

    async def source():
        yield packet(owner, 0)
        entered.set()
        await release.wait()

    await owner.start_fixture(source(), model_adapter=UnknownMockAdapter())
    await entered.wait()
    original = datetime.now(UTC)
    stamp = original
    tick = 10.0
    monkeypatch.setattr(runtime_store, "utc_now", lambda: stamp)
    monkeypatch.setattr(
        stream_service,
        "time",
        SimpleNamespace(monotonic=lambda: tick, process_time=time.process_time),
    )
    owner.started_at = 0
    try:
        await owner.publish(force=True)
        first = owner.snapshot()
        tick = 11.0
        stamp -= timedelta(seconds=0.471)
        await owner.publish(force=True)
        second = owner.snapshot()
        assert first["network"]["capture_uptime_seconds"] == 10
        assert second["network"]["capture_uptime_seconds"] == 11
        assert owner.aggregator.table.flows  # Wall-clock changes do not expire flows.
        assert second["network"]["inference_count"] == 0
        assert not second["collection_live"]
    finally:
        release.set()
        await owner.task
    assert owner.store.runtime.verify_audit()
    assert owner.metrics["capture_uptime_seconds"] >= 0


def test_gui_monotonic_observation_order_ignores_utc_order():
    # Same acceptance path used by the Tk view; no display needed here.
    view = SimpleNamespace(observation_started_ns=0)
    assert LiveView.accept_observation(view, {"observation_started_ns": 20, "utc": "earlier"})
    assert not LiveView.accept_observation(view, {"observation_started_ns": 19, "utc": "later"})
