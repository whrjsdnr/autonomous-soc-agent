"""Actual WSLg windows; auth/privilege launcher mocked, all packets synthetic."""

import asyncio
import tkinter as tk

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.security_ai.operational.network_capture.total_session import verify_bundle
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths
from tests.total_monitoring_support import total_source
from tests.unit.streaming_network.test_auth import Process


@pytest.mark.asyncio
async def test_one_command_gui_auto_handoff_is_mocked_and_failure_visible(tmp_path, monkeypatch):
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
    root = tk.Tk()
    app = Desktop(
        root,
        GUIConfig(data_directory=tmp_path, total_approved_sha=verify_bundle()["total_helper.py"]),
    )
    calls = []

    async def launch(*args, **kw):
        calls.append((args, kw))
        return Process(1)

    app.worker.backend.total_auth.launcher = launch
    try:
        await idle(root, app)
        await asyncio.sleep(0.5)
        await idle(root, app)
        assert app.page == "Total Monitoring"
        assert len(calls) == 1 and calls[0][0][:2] == ("/usr/bin/sudo", "-n")
        state = await asyncio.wrap_future(app.worker.submit("total_status"))
        assert not state["collection_live"] and state["state"] == "ERROR"
        assert state["os_auth"]["state"] == "AUTH_EXPIRED_OR_HELPER_START_FAILED"
    finally:
        await close(root, app)


@pytest.mark.asyncio
async def test_total_gui_real_models_dns_details_exports_and_restart(tmp_path, monkeypatch):
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path))
    owner = app.worker.backend.total_monitoring
    try:
        await idle(root, app)
        app.navigate("Total Monitoring")

        async def run():
            await owner.start_fixture(total_source(owner))
            await owner.task
            return owner.snapshot()

        future = asyncio.run_coroutine_threadsafe(run(), app.worker.loop)
        while not future.done():
            root.update()
            await asyncio.sleep(0.03)
        state = future.result()
        app.live_view.render(state)
        assert app.live_view.counts.counts == {"quality": 2, "edge": 2}
        assert "MATCHED_RESPONSE" in app.live_view.metrics.get()
        assert "DNS9 BLOCKED" in app.live_view.metrics.get()
        monkeypatch.setattr(
            "soc_agent.gui.live_view.filedialog.asksaveasfilename",
            lambda **kw: str(tmp_path / "export.json"),
        )
        app.live_view.export("json")
        await idle(root, app)
        assert (tmp_path / "export.json").is_file()
        for geometry in ("1920x1080", "1366x768", "1280x720"):
            root.geometry(geometry)
            root.update()
            assert app.live_view.instructions.winfo_width() > 0
    finally:
        await close(root, app)
