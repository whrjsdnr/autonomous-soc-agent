"""Actual WSLg callbacks, isolated archive-full root; no capture or auth launch."""

import asyncio
import tkinter as tk

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths


@pytest.mark.asyncio
async def test_archive_failure_is_visible_and_stale_ready_never_requests_auth(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", research_paths)
    directory = tmp_path / "gui"
    directory.mkdir(mode=0o700)
    sessions = directory / "total-monitoring"
    sessions.mkdir(mode=0o700)
    for i in range(8):
        (sessions / f"session-fixture-{i}").mkdir(mode=0o700)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=directory))
    callbacks = []
    root.report_callback_exception = lambda *args: callbacks.append(args[0].__name__)

    async def forbidden(*args, **kwargs):
        pytest.fail("Preparation failure must never launch OS authentication")

    app.worker.backend.total_auth.launcher = forbidden
    try:
        await idle(root, app)
        app.navigate("Total Monitoring")
        await idle(root, app)
        view = app.live_view
        view.rate_policy.set("balanced-v2")
        view.start_button.invoke()
        await idle(root, app)
        state = await asyncio.wrap_future(app.worker.submit("total_status"))
        view.render(state)
        assert state["last_error"] == "STREAM_ARCHIVAL_REQUIRED"
        assert state["preparation_phase"] == "SESSION_ARCHIVE"
        assert state["session_id"] is None and not state["listener_ready"]
        text = view.instructions.get("1.0", "end")
        assert "STREAM_ARCHIVAL_REQUIRED" in text and "NOT_PREPARED" in text
        assert "Environment unavailable" not in text
        assert "LISTENER READY" not in view.headline.get()
        assert "STREAM_ARCHIVAL_REQUIRED" in view.metrics.get()
        assert str(view.copy_button.cget("state")) == "disabled" and not view.command
        assert state["network"].get("inference_count", 0) == 0
        assert state["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
        view.started(
            {
                "listener_ready": True,
                "command": "FIXTURE_NEVER_EXECUTABLE",
                "helper_sha256": "a" * 64,
                "session_id": "old-session",
                "observation_started_ns": view.observation_started_ns - 1,
            }
        )
        assert not view.command and "LISTENER READY" not in view.headline.get()
        app.call("total_stop", callback=view.render)
        await idle(root, app)
        view.restart()
        await idle(root, app)
        assert "STREAM_ARCHIVAL_REQUIRED" in view.instructions.get("1.0", "end")
        assert len(list(sessions.glob("session-*"))) == 8
        assert not callbacks
    finally:
        await close(root, app)
