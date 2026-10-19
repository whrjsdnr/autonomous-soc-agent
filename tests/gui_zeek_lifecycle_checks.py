"""Actual WSLg controller UX; mocked environment, no authentication/capture/model load."""

import json
import os
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_handoff_copy_stop_generation_crash_and_gui_close(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("GUI AUTHENTICATION OR CAPTURE FORBIDDEN")

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", forbidden)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path, collector_type="zeek-live"))
    session = None
    try:
        await idle(root, app)
        assert app.worker.backend._owners == {}
        app.start()
        await idle(root, app)
        first = app.snapshot.copy()
        assert first["command_valid"] and first["handoff_listener_ready"]
        assert first["controller_alive"] and not first["collection_live"]
        app.copy_command()
        await idle(root, app)
        assert root.clipboard_get() == app.command
        for page in SCREENS:
            app.navigate(page, refresh=False)
            for w, h in ((1920, 1080), (1366, 768)):
                root.geometry(f"{w}x{h}")
                root.update()
                assert root.winfo_width() == w
                if os.getenv("SOC_ZEEK_LIFECYCLE_SCREENSHOTS"):
                    capture(
                        root,
                        Path(os.environ["SOC_ZEEK_LIFECYCLE_SCREENSHOTS"])
                        / f"{page.lower().replace(' ', '-')}-handoff-ready-{w}.png",
                    )
        app.navigate("System", refresh=False)
        assert "COMMAND_VALID" in app.system.get("1.0", "end")
        app.call("collector_stop", callback=app.render)
        await idle(root, app)
        assert not app.command and app.copy_button.instate(["disabled"])
        app.start()
        await idle(root, app)
        second = app.snapshot.copy()
        assert second["controller_generation"] != first["controller_generation"]
        assert second["session_id"] != first["session_id"]
        app.render(first)
        assert app.snapshot["session_id"] == second["session_id"]
        session = app.worker.backend._owners["zeek_collector"].directory
        with monkeypatch.context() as m:
            m.setattr(app.worker.thread, "is_alive", lambda: False)
            app.refresh()
            assert not app.command and app.snapshot["state"] == "ERROR"
            assert app.copy_button.instate(["disabled"])
            assert app.snapshot["last_error"] == "ZEEK_CONTROLLER_NOT_RUNNING"
        assert app.worker.backend.model_service is None
    finally:
        await close(root, app)
    assert not app.worker.thread.is_alive()
    assert json.loads((session / "stop.request").read_text())["reason"] == "GUI_CLOSE"
