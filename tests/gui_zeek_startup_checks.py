"""Real unprivileged Tk window; mocked authentication and capture runner only."""

import json
import os
import signal
import tkinter as tk

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from soc_agent.security_ai.collectors.startup import Startup
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_shared_worker_ready_charts_and_fresh_approval_after_stop(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", lambda: None)
    s = Startup(GUIConfig(data_directory=tmp_path, collector_type="zeek-live"))
    s.prepare()
    s.authenticate()
    called = []

    async def admission(runner):
        assert runner._authenticated_plan == runner.plan.identity
        called.append("start_mock_only")
        return await s.worker.backend.production_status()

    monkeypatch.setattr(s.worker.backend, "zeek_launch_authenticated", admission)
    root = tk.Tk()
    app = Desktop(root, s.config, worker=s.worker, on_ready=s.gui_ready)
    app.terminal_managed = True
    try:
        await idle(root, app)
        assert called == ["start_mock_only"]
        assert app.worker is s.worker and s.gui_started
        assert not app.snapshot["collection_live"]
        first = app.snapshot["session_id"]
        for page in SCREENS:
            app.navigate(page, refresh=False)
            for size in ("1366x768", "1920x1080"):
                root.geometry(size)
                root.update()
        app.navigate("System", refresh=False)
        assert app.copy_button.instate(["disabled"])
        assert app.start_button.instate(["disabled"])
        assert "NOT_OBSERVED" in app.system.get("1.0", "end")
        app.call("collector_stop", callback=app.render)
        await idle(root, app)
        app.start()
        await idle(root, app)
        assert app.snapshot["session_id"] == first and called == ["start_mock_only"]
        assert "fresh terminal" in app.status.get()
    finally:
        await close(root, app)
    assert s.finish() and not s.worker.thread.is_alive()


def test_sigint_routes_to_user_stop_in_prepared_gui(tmp_path, monkeypatch):
    from soc_agent.gui.__main__ import main

    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", lambda: None)
    s = Startup(GUIConfig(data_directory=tmp_path, collector_type="zeek-live"))
    s.prepare()
    s.authenticate()

    async def admission(runner):
        assert runner._authenticated_plan == runner.plan.identity
        return await s.worker.backend.production_status()

    monkeypatch.setattr(s.worker.backend, "zeek_launch_authenticated", admission)
    original = tk.Tk

    def window():
        root = original()

        def interrupt():
            if s.gui_started:
                os.kill(os.getpid(), signal.SIGINT)
            else:
                root.after(25, interrupt)

        root.after(25, interrupt)
        return root

    monkeypatch.setattr(tk, "Tk", window)
    assert main(["--collector", "zeek-live", "--data-directory", str(tmp_path)], prepared=s) == 0
    assert s.finish() and not s.worker.thread.is_alive()
    assert json.loads((s.runner.directory / "stop.request").read_text())["reason"] == "USER_STOP"
