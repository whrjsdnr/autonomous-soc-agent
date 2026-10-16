"""Real WSLg Tk window, no privilege launch, network traffic or AF_PACKET socket."""

import asyncio
import os
import tkinter as tk

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import idle_source


@pytest.mark.asyncio
async def test_streaming_gui_auth_fallback_fixture_models_and_restart(tmp_path, monkeypatch):
    assert os.geteuid() != 0
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    errors = []
    root.report_callback_exception = lambda *args: errors.append(args[0].__name__)
    try:
        await idle(root, app)
        app.navigate("Streaming Network")
        await idle(root, app)
        view = app.live_view
        owner = app.worker.backend.streaming_monitoring
        app.worker.backend.streaming_auth.inspector = lambda: {"status": "OS_AUTH_UI_UNAVAILABLE"}
        view.start_button.invoke()
        view.start_button.invoke()
        await idle(root, app)
        assert view.command and "stream_helper" in view.command
        assert owner.capture.listener_ready()
        assert "unavailable" in app.notice.get().lower()
        state = await asyncio.wrap_future(app.worker.submit("stream_status"))
        assert not state["collection_live"]
        assert not state["research"]["records"]
        assert str(view.start_button.cget("state")) == "disabled"
        app.call("stream_stop", callback=view.render)
        await idle(root, app)
        assert not view.command
        assert not owner.capture.listener_ready()

        async def fixture():
            await owner.start_fixture(idle_source(owner), policy=StreamPolicy(seconds=120))
            await owner.task
            return await app.worker.backend.stream_status()

        future = asyncio.run_coroutine_threadsafe(fixture(), app.worker.loop)
        while not future.done():
            root.update()
            await asyncio.sleep(0.03)
        state = future.result()
        assert len(state["research"]["records"]) == 2
        view.render(state)
        assert "FIXTURE" in view.traffic.source
        assert view.counts.counts == {"quality": 1, "edge": 1}
        assert "BLOCKED" in view.headline.get()
        assert "RESEARCH_ONLY" in view.metrics.get()
        assert "UNKNOWN" in view.metrics.get()  # no fake DNS/kernel counts for fixture
        for geometry in ("1920x1080", "1366x768", "1280x720"):
            root.geometry(geometry)
            root.update()
            assert root.winfo_ismapped()
            assert view.start_button.winfo_exists()
            assert view.instructions.winfo_width() > 0
        assert not errors, errors
    finally:
        await close(root, app)
    assert owner.task.done()
    # Fresh Tk interpreter, restored receipts only; no capture or new model call.
    import gc

    gc.collect()
    second = tk.Tk()
    reopened = Desktop(second, GUIConfig(data_directory=tmp_path / "gui"))
    try:
        await idle(second, reopened)
        reopened.navigate("Streaming Network")
        await idle(second, reopened)
        reopened.call("stream_restore", callback=reopened.live_view.render)
        await idle(second, reopened)
        snapshot = await asyncio.wrap_future(reopened.worker.submit("stream_status"))
        assert snapshot["state"] == "RETAINED_STREAM_NOT_LIVE"
        assert snapshot["network"]["inference_count"] == 0
        assert snapshot["network"]["inferences_per_minute"] is None
        assert len(snapshot["research"]["records"]) == 2
        assert "RETAINED" in reopened.live_view.counts.heading
        assert not snapshot["collection_live"]
    finally:
        await close(second, reopened)
