"""Actual WSLg widgets, synthetic load, UNKNOWN mock model, no privilege handoff."""

import asyncio
import json
import os
import threading
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import UnknownMockAdapter, packet
from tests.total_rate_profile import measure


@pytest.mark.asyncio
async def test_gui_rate_health_exclusions_stop_and_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path))
    owner = app.worker.backend.total_monitoring
    ready, release = threading.Event(), threading.Event()

    class Delayed(UnknownMockAdapter):
        async def infer(self, request):
            while not release.is_set():
                await asyncio.sleep(0.01)
            return await super().infer(request)

    async def source():
        for port in range(1000, 1012):
            for t in (0, 0.5, 31):
                yield packet(owner, t, port=port)
        await owner.publish(force=True)
        ready.set()
        while not release.is_set():
            await asyncio.sleep(0.01)

    try:
        await idle(root, app)
        app.navigate("Total Monitoring")
        future = asyncio.run_coroutine_threadsafe(
            owner.start_fixture(source(), model_adapter=Delayed()), app.worker.loop
        )
        deadline = time.monotonic() + 20
        while not ready.is_set():
            assert time.monotonic() < deadline
            root.update()
            await asyncio.sleep(0.02)
        future.result()
        state = await asyncio.wrap_future(app.worker.submit("total_status"))
        app.live_view.render(state)
        root.update()
        text = app.live_view.metrics.get()
        assert "Approved rate 128 raw frames/s" in text
        assert "burst 256" in text and "observed raw frames/s UNKNOWN" in text
        assert "Rate budget FIXTURE_NO_CAPTURE" in text
        assert "Backpressure HIGH" in text
        assert "Not inferred (capacity/circuit) 4" in text
        assert "DNS9 BLOCKED" in text
        assert app.live_view.counts.counts == {"quality": 0, "edge": 0}
        profile = measure(lambda: (app.live_view.render(state), root.update_idletasks()), 20)
        if os.getenv("SOC_RATE_GUI_PROFILE"):
            Path(os.environ["SOC_RATE_GUI_PROFILE"]).write_text(json.dumps(profile, indent=2))
        release.set()
        app.call("total_stop", callback=app.live_view.render)
        await idle(root, app)
        assert owner.task.done()
        app.call("total_restore", callback=app.live_view.render)
        await idle(root, app)
        assert "Backpressure RETAINED_NOT_LIVE" in app.live_view.metrics.get()
        assert "Worker health STOPPED" in app.live_view.metrics.get()
        assert owner.metrics["inference_count"] == 0
    finally:
        release.set()
        await close(root, app)
