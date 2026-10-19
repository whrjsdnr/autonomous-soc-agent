"""Actual WSLg widgets backed by synthetic metadata only; no privilege handoff."""

import asyncio
import threading
import tkinter as tk

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import packet
from tests.total_monitoring_support import dns_packet


@pytest.mark.asyncio
async def test_total_degraded_stop_and_retained_quarantine_are_visible(tmp_path, monkeypatch):
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path))
    owner = app.worker.backend.total_monitoring
    prepared = threading.Event()

    async def source():
        yield packet(owner, 0)
        yield packet(owner, 1)
        yield packet(owner, 0.999989)
        yield dns_packet(owner, 2)
        yield dns_packet(owner, 2.5, response=True)
        yield dns_packet(owner, 2.6, malformed=True)
        prepared.set()
        while not owner.stop_requested:
            await asyncio.sleep(0.02)

    try:
        await idle(root, app)
        app.navigate("Total Monitoring")
        future = asyncio.run_coroutine_threadsafe(owner.start_fixture(source()), app.worker.loop)
        while not future.done() or not prepared.is_set():
            root.update()
            await asyncio.sleep(0.02)
        future.result()
        snapshot = await asyncio.wrap_future(app.worker.submit("total_status"))
        app.live_view.render(snapshot)
        root.update()
        assert "Integrity DEGRADED" in app.live_view.headline.get()
        text = app.live_view.metrics.get()
        assert "Quarantined flow keys 1" in text
        assert "DNS diagnostic status DEGRADED" in text
        assert "FIXTURE_NO_CAPTURE" in text and "DNS9 BLOCKED" in text
        assert "LIVE_COLLECTION" not in app.live_view.headline.get()
        assert app.live_view.counts.counts == {"quality": 0, "edge": 0}
        assert str(app.live_view.start_button.cget("state")) == "disabled"
        app.call("total_stop", callback=app.live_view.render)
        await idle(root, app)
        assert owner.task.done()
        assert "Integrity STOPPED" in app.live_view.headline.get()
        app.call("total_restore", callback=app.live_view.render)
        await idle(root, app)
        assert "RECOVERY_PENDING" in app.live_view.headline.get()
        assert "Quarantined flow keys 1" in app.live_view.metrics.get()
        assert owner.metrics["inference_count"] == 0
    finally:
        await close(root, app)
